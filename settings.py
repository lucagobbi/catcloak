from pydantic import BaseModel

from cat.mad_hatter.decorators import plugin

class CatcloakSettings(BaseModel):
    server_url: str
    realm: str
    client_id: str
    client_secret: str

@plugin
def settings_model():
    return CatcloakSettings
