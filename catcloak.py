from cat.looking_glass.cheshire_cat import CheshireCat
from cat.mad_hatter.decorators import tool, hook, plugin
from cat.factory.auth_handler import AuthHandlerConfig
from cat.factory.custom_auth_handler import BaseAuthHandler
from cat.auth.permissions import (
    AuthPermission, AuthResource, AuthUserInfo, get_base_permissions, get_full_permissions
)

from pydantic import BaseModel, ConfigDict
from typing import List, Type
from keycloak import KeycloakOpenID

ccat = CheshireCat()


@hook(priority=0)
def factory_allowed_auth_handlers(allowed: List[AuthHandlerConfig], cat) -> List:
    allowed.append(KeycloakAuthHandlerConfig)
    return allowed


class KeycloakAuthHandler(BaseAuthHandler):

    async def authorize_user_from_jwt(
        self, token: str, auth_resource: AuthResource, auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        settings = ccat.mad_hatter.get_plugin().load_setting()

        keycloak_openid = KeycloakOpenID(
            server_url=settings["server_url"],
            client_id=settings["client_id"],
            realm_name=settings["realm"],
            client_secret_key=settings["client_secret"]
        )

        try:
            token_info = keycloak_openid.decode_token(token)
            return AuthUserInfo(

            )
        except Exception as e:
            ccat.log.error(f"Error decoding token: {e}")
            return None


    async def authorize_user_from_key(
        self,
        user_id: str,
        api_key: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission,
    ) -> AuthUserInfo | None:
        return None



class KeycloakAuthHandlerConfig(AuthHandlerConfig):
    _pyclass: Type = KeycloakAuthHandler

    model_config = ConfigDict(
        json_schema_extra={
            "humanReadableName": "Keycloak Auth Handler",
            "description": "Delegate auth to a Keycloak instance."
        }
    )
