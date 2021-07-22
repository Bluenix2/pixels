import logging

from fastapi import HTTPException, Request
from fastapi.security import HTTPBasic
from passlib import CryptContext

from pixels.models import AuthState

log = logging.getLogger(__name__)
ctx = CryptContext(schemes=["argon2"])


class BasicAuth(HTTPBasic):
    """Dependency for enforcing Basic authentication."""

    def __init__(self, auto_error: bool = True, is_mod_endpoint: bool = False):
        super().__init__(auto_error=auto_error)
        self.is_mod_endpoint = is_mod_endpoint

    async def __call__(self, request: Request):
        """Check if the supplied username and password is valid."""
        credentials = await super().__call__(request)

        password = await request.state.db_conn.fetchval(
            "SELECT password FROM basic_auth WHERE username = $1",
            credentials.username
        )
        match = ctx.verify(credentials.password, password)

        if not match:
            raise HTTPException(status_code=403, detail=AuthState.INVALID_TOKEN.value)

        user = await request.state.db_conn.fetchrow(
          "SELECT user_id, is_banned, is_mod FROM users"
          "WHERE user_id = (SELECT user_id FROM basic_auth WHERE username = $1)",
          credentials.username
        )

         # Handle bad scenarios
        if user is None:
            raise HTTPException(status_code=403, detail=AuthState.INVALID_TOKEN.value)
        elif user["is_banned"]:
            raise HTTPException(status_code=403, detail=AuthState.BANNED.value)
        elif self.is_mod_endpoint and not user["is_mod"]:
            raise HTTPException(status_code=403, detail=AuthState.NEEDS_MODERATOR.value)

        request.state.user_id = int(user["user_id"])
        return credentials
