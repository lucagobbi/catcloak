from cat.looking_glass.cheshire_cat import CheshireCat
from cat.mad_hatter.decorators import hook
from cat.factory.auth_handler import AuthHandlerConfig
from cat.factory.custom_auth_handler import BaseAuthHandler
from cat.auth.permissions import (
    AuthPermission, AuthResource, AuthUserInfo, get_base_permissions
)
from cat.log import log

from pydantic import ConfigDict
from typing import List, Type, Dict, Any
from keycloak import KeycloakOpenID

ccat = CheshireCat()


@hook(priority=0)
def factory_allowed_auth_handlers(allowed: List[AuthHandlerConfig], cat) -> List:
    allowed.append(KeycloakAuthHandlerConfig)
    return allowed


class KeycloakAuthHandler(BaseAuthHandler):

    def __init__(self):
        self.keycloak_openid = None
        self.settings = None
        self.user_mapping = None
        self.permission_mapping = None
        self.kc_permissions = {}

    def initialize(self):
        if not self.settings:
            self.settings = ccat.mad_hatter.get_plugin().load_settings()
            self.user_mapping = self.settings.get("user_mapping", {})
            self.permission_mapping = self.settings.get("permission_mapping", {})
            self.keycloak_openid = KeycloakOpenID(
                server_url=self.settings["server_url"],
                client_id=self.settings["client_id"],
                realm_name=self.settings["realm"],
                client_secret_key=self.settings["client_secret"]
            )

    async def authorize_user_from_jwt(
        self, token: str, auth_resource: AuthResource, auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        try:
            self.initialize()
            token_info = await self.keycloak_openid.a_decode_token(token)
            user_info = self.map_user_data(token_info)
            self.map_permissions(token_info, user_info)

            log.debug(f"User info: {user_info}")

            if not self.permission_mapping:
                user_info.permissions = get_base_permissions()
                return user_info

            if self.has_permission(user_info, auth_resource, auth_permission):
                return user_info
            return None
        except Exception as e:
            log.error(f"Error processing token: {e}")
            return None

    async def authorize_user_from_key(
        self, user_id: str, api_key: str, auth_resource: AuthResource, auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        log.debug("KeycloakAuthHandler does not support API keys.")
        return None

    def map_user_data(self, token_info: Dict[str, Any]) -> AuthUserInfo:
        extra = {key: self.get_nested_value(token_info, path) 
                 for key, path in self.user_mapping.items() 
                 if key not in ["id", "name", "roles"]}

        return AuthUserInfo(
            id=self.get_nested_value(token_info, self.user_mapping.get("id", "sub")),
            name=self.get_nested_value(token_info, self.user_mapping.get("name", "preferred_username")),
            extra=extra
        )

    def map_permissions(self, token_info: Dict[str, Any], user_info: AuthUserInfo):
        roles_path = self.user_mapping.get("roles", "realm_access.roles")
        roles = self.get_nested_value(token_info, roles_path) or []
        
        roles_key = tuple(sorted(roles))
        
        if roles_key in self.kc_permissions:
            user_info.permissions = self.kc_permissions[roles_key]
            return

        permissions = {}
        for role in roles:
            if role in self.permission_mapping:
                for resource, perms in self.permission_mapping[role].items():
                    if resource not in permissions:
                        permissions[resource] = set()
                    permissions[resource].update(perms)
        
        permissions = {resource: list(perms) for resource, perms in permissions.items()}
        self.kc_permissions[roles_key] = permissions
        user_info.permissions = permissions

    def has_permission(self, user_info: AuthUserInfo, auth_resource: AuthResource, auth_permission: AuthPermission) -> bool:
        if auth_resource.value not in user_info.permissions:
            log.error(f"User {user_info.id} does not have permission to access {auth_resource.value}")
            return False
        if auth_permission.value not in user_info.permissions[auth_resource.value]:
            log.error(f"User {user_info.id} does not have permission to access {auth_resource.value} with {auth_permission.value}")
            return False
        return True

    @staticmethod
    def get_nested_value(data: Dict[str, Any], path: str) -> Any:
        keys = path.split('.')
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                return None
        return data


class KeycloakAuthHandlerConfig(AuthHandlerConfig):
    _pyclass: Type = KeycloakAuthHandler

    model_config = ConfigDict(
        json_schema_extra={
            "humanReadableName": "Keycloak Auth Handler",
            "description": "Delegate auth to a Keycloak instance."
        }
    )
