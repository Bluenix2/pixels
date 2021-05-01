import asyncio
import logging
from time import time

from aioredis import Redis
from asyncpg import Connection

from pixels import constants

log = logging.getLogger(__name__)


# How long before considering that the key is deadlocked and won't be released
KEY_TIMEOUT = 10


class Canvas:
    """Class used for interacting with the canvas."""

    def __init__(self, redis: Redis):
        self.redis = redis

    @staticmethod
    async def _try_acquire_lock(conn: Connection) -> bool:
        """
        Try to acquire the sync lock from the cache state.

        Returns True if the lock has been acquired. The lock functions as a spinlock.
        """
        # We try to set the lock but use a self join to return the previous state.
        previous_record, = await conn.fetch(
            """UPDATE cache_state x
            SET sync_lock = now()
            FROM (SELECT sync_lock FROM cache_state FOR UPDATE) y
            RETURNING y.sync_lock AS previous_state
            """)
        return previous_record["previous_state"] is None

    async def _populate_cache(self, conn: Connection) -> None:
        """Populate the cache and discard old values."""
        start_time = time()

        transaction = self.redis.multi_exec()

        records = await conn.fetch("SELECT x, y, rgb FROM current_pixel ORDER BY x, y")
        # Iterate every line and store the associated cache line
        for line in range(constants.height):
            line_bytes = bytearray(3 * constants.width)

            # Get the current row from the records
            for position, record in enumerate(records[line * constants.width:(line + 1) * constants.width]):
                line_bytes[position * 3:(position + 1) * 3] = bytes.fromhex(record["rgb"])

            transaction.set(f"canvas-line-{line}", line_bytes)

        results = await transaction.execute()
        # Make sure that nothing errored out
        if not all(results):
            raise IOError("Error while updating the cache.")

        log.info(f"Cache updated finished! (took {time() - start_time}s)")
        await conn.execute("UPDATE cache_state SET last_synced = now()")

    @staticmethod
    async def is_cache_out_of_date(conn: Connection) -> bool:
        """Return true if the cache can be considered out of date."""
        record, = await conn.fetch("SELECT last_modified, last_synced FROM cache_state")
        return record["last_modified"] > record["last_synced"]

    async def sync_cache(self, conn: Connection) -> None:
        """Make sure that the cache is up-to-date."""
        lock_cleared = False

        while await self.is_cache_out_of_date(conn):
            log.info("Cache will be updated")

            if await self._try_acquire_lock(conn) or lock_cleared:
                log.info("Lock acquired. Starting synchronisation.")
                lock_cleared = False
                try:
                    await self._populate_cache(conn)
                # Use a finally block to make sure that the lock is freed
                finally:
                    await conn.execute("UPDATE cache_state SET sync_lock = NULL")
            else:
                # Another process is already syncing the cache, let's just wait patiently.
                log.info("Lock in use. Waiting for process to be finished")

                while True:
                    record, = await conn.fetch("SELECT sync_lock FROM cache_state")

                    if record["sync_lock"] is None:
                        break

                    # If it has been too long since the lock has been set
                    # we consider it as deadlocked and clear it
                    result = await conn.execute(
                        f"""UPDATE cache_state
                        SET sync_lock = now()
                        WHERE now() - sync_lock > interval '{KEY_TIMEOUT} seconds'"""
                    )
                    if result.split()[1] == "1":
                        log.warning("Lock considered as deadlocked. Clearing it.")
                        await conn.execute("UPDATE cache_state SET sync_lock = now()")
                        lock_cleared = True
                        break

                    await asyncio.sleep(.1)
        else:
            log.debug("Cache is up-to-date")

    async def set_pixel(self, conn: Connection, x: int, y: int, rgb: str, user_id: int) -> None:
        """Set the provided pixel."""
        await self.sync_cache(conn)

        # Get the line and update the pixel
        line = bytearray(await self.redis.get(f"canvas-line-{y}"))
        line[x * 3:(x + 1) * 3] = bytes.fromhex(rgb)

        async with conn.transaction():
            # Insert the pixel into the database
            await conn.execute(
                """
                INSERT INTO pixel_history (x, y, rgb, user_id, deleted) VALUES ($1, $2, $3, $4, false);
            """,
                x,
                y,
                rgb,
                user_id
            )

            # Update the cache
            await self.redis.set(
                f"canvas-line-{y}",
                line
            )
            await conn.execute("UPDATE cache_state SET last_synced = now()")

    async def get_pixels(self) -> bytearray:
        """Returns the whole board."""
        buffer = bytearray(constants.width * constants.height * 3)

        # Aggregate every cache line into a unique buffer
        for line in range(constants.height):
            buffer[
                line * 3 * constants.width:(line + 1) * 3 * constants.width
            ] = await self.redis.get(f"canvas-line-{line}")

        return buffer
