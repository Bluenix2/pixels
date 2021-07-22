from .basic import BasicAuth
from .jwt import JWTBearer

# The current authorization method
UserAuth = JWTBearer
