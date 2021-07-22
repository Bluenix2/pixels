from fastapi import Request
from fastapi.security.utils import get_authorization_scheme_param

from .basic import BasicAuth
from .jwt import JWTBearer


class UserAuth:
    """Dependency for routes to enforce any kind of supported authentication."""

    def __init__(self, is_mod_endpoint: bool = False):
        self.is_mod_endpoint = is_mod_endpoint

        self.schemes = {
          'Basic': BasicAuth(),
          'Bearer': self.jwt = JWTBearer(),
        }

    async def __call__(self, request: Request):
        authorization = request.headers.get('Authorization')
        scheme, param = get_authorization_scheme_param(authorization)

        try:
            res = await self.schemes[scheme](request)
        except KeyError:
            raise HTTPException(status_code=401, detail="Unsupported authentication method.")

        return res
