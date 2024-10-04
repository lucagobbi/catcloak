from typing import Dict, List

from pydantic import BaseModel, Field

from cat.mad_hatter.decorators import plugin
from cat.auth.permissions import get_full_permissions, get_base_permissions

class CatcloakSettings(BaseModel):
    server_url: str
    realm: str
    client_id: str
    client_secret: str

    user_mapping: Dict[str, str] = Field(
        title="User Data Mapping",
        default=dict(
            id="sub",
            name="preferred_username",
            email="email",
            roles="realm_access.roles",
            given_name="given_name",
            family_name="family_name"
        ),
        extra={"type": "TextArea"}
    )

    permission_mapping: Dict[str, Dict[str, List[str]]] = Field(
        title="Permission Mapping",
        default=dict(
            admin=get_full_permissions(),
            user=get_base_permissions()
        ),
        extra={"type": "TextArea"}
    )


@plugin
def settings_model():
    return CatcloakSettings