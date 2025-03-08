from cat.mad_hatter.decorators import hook
from cat.factory.auth_handler import AuthHandlerConfig
from cat.factory.custom_auth_handler import BaseAuthHandler
from cat.auth.permissions import (
    AuthPermission, AuthResource, AuthUserInfo, get_base_permissions
)
from cat.log import log

from pydantic import ConfigDict, Field
from typing import List, Type, Dict, Any, Literal
from keycloak import KeycloakOpenID
from cachetools import TTLCache
from time import time


@hook(priority=0)
def factory_allowed_auth_handlers(allowed: List[AuthHandlerConfig], cat) -> List:
    allowed.append(KeycloakAuthHandlerConfig)
    return allowed


class KeycloakAuthHandler(BaseAuthHandler):

    def __init__(self, **config):
        self.user_mapping = config.get("user_mapping", {})
        self.permission_mapping = config.get("permission_mapping", {})
        self.keycloak_openid = KeycloakOpenID(
            server_url=config["server_url"],
            client_id=config["client_id"],
            realm_name=config["realm"],
            client_secret_key=config["client_secret"]
        )
        self.kc_permissions = {}
        self.token_cache = TTLCache(maxsize=1000, ttl=300)
        self.user_info_cache = TTLCache(maxsize=1000, ttl=300)

    def authorize_user_from_jwt(
            self, token: str, auth_resource: AuthResource, auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        try:

            if token in self.token_cache:
                token_info, expiration = self.token_cache[token]
                if time() < expiration:
                    user_info = self.user_info_cache.get(token)
                    if user_info and self.has_permission(user_info, auth_resource, auth_permission):
                        return user_info

            token_info = self.keycloak_openid.decode_token(token)

            expiration = token_info['exp']
            self.token_cache[token] = (token_info, expiration)

            user_info = self.map_user_data(token_info)
            self.map_permissions(token_info, user_info)

            log.debug(f"User info: {user_info}")

            self.user_info_cache[token] = user_info

            if not self.permission_mapping:
                user_info.permissions = get_base_permissions()
                return user_info

            if self.has_permission(user_info, auth_resource, auth_permission):
                return user_info
            return None
        except Exception as e:
            log.error(f"Error processing token: {e}")
            return None

    def authorize_user_from_key(
            self, protocol: Literal["http", "websocket"], user_id: str, api_key: str, auth_resource: AuthResource,
            auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        log.warning("KeycloakAuthHandler does not support API keys.")
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
        kc_roles = self.get_nested_value(token_info, roles_path) or []

        roles_key = tuple(sorted(kc_roles))

        if roles_key in self.kc_permissions:
            user_info.permissions = self.kc_permissions[roles_key]
            return

        permissions = {}
        for role in kc_roles:
            if role in self.permission_mapping:
                for resource, perms in self.permission_mapping[role].items():
                    if resource not in permissions:
                        permissions[resource] = set()
                    permissions[resource].update(perms)

        permissions = {resource: list(perms) for resource, perms in permissions.items()}
        self.kc_permissions[roles_key] = permissions
        user_info.permissions = permissions

    def has_permission(self, user_info: AuthUserInfo, auth_resource: AuthResource,
                       auth_permission: AuthPermission) -> bool:
        user_permissions = user_info.permissions.get(auth_resource.value, [])
        if auth_permission.value not in user_permissions:
            log.error(
                f"User {user_info.id} does not have permission to access {auth_resource.value} with {auth_permission.value}")
            return False
        return True

    @staticmethod
    def get_nested_value(data: Dict[str, Any], path: str) -> Any:
        for key in path.split('.'):
            if isinstance(data, dict):
                data = data.get(key)
        return data


class KeycloakAuthHandlerConfig(AuthHandlerConfig):
    _pyclass: Type = KeycloakAuthHandler

    server_url: str = Field(..., description="The URL of the Keycloak server.")
    realm: str = Field(..., description="The realm to use.")
    client_id: str = Field(..., description="The client ID to use.")
    client_secret: str = Field(..., description="The client secret to use.")
    user_mapping: Dict[str, str] = Field(..., description="The mapping of user data from the token to the user model.",
                                         extra={"type": "TextArea"})
    permission_mapping: Dict[str, Any] = Field(..., description="The mapping of Keycloak roles to Cat permissions.",
                                               extra={"type": "TextArea"})

    model_config = ConfigDict(
        json_schema_extra={
            "humanReadableName": "Keycloak Auth Handler",
            "description": "Delegate auth to a Keycloak instance."
        }
    )
