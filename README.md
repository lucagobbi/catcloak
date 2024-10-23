# Catcloak

<img src="./assets/catcloak.png" width=400>

[![awesome plugin](https://custom-icon-badges.demolab.com/static/v1?label=&message=awesome+plugin&color=383938&style=for-the-badge&logo=cheshire_cat_ai)](https://)

Catcloak is a Cheshire Cat AI plugin that integrates Keycloak authentication into your Cheshire Cat instance, providing robust user management and access control.

## Features

- Integration with Keycloak for user authentication
- User data mapping from Keycloak to Cheshire Cat
- Customizable permission mapping based on Keycloak roles
- Support for JWT token-based authentication

## Configuration

First of all, be sure that your Cat installation is properly secured following these [instructions](https://cheshire-cat-ai.github.io/docs/production/auth/authentication/) in the official Cheshire Cat documentation.

Configure the KeycloakAuthHandlerConfig sending an HTTP PUT request to the AuthHandler endpoint specifying the following parameters:

1. Keycloak connection details:
   - `server_url`: Your Keycloak server URL
   - `realm`: Your Keycloak realm name
   - `client_id`: Your Keycloak client ID
   - `client_secret`: Your Keycloak client secret

2. `user_mapping` to map Keycloak user data. You can pass whatever info you want the Cheshire Cat to know about the user.

3. `permission_mapping` to set up role-based access control. If not defined, the user will have the base permissions.

Use the following curl command as an example:

```bash
curl --location --request PUT 'http://localhost:1865/auth_handler/settings/KeycloakAuthHandlerConfig' \
--header 'Content-Type: application/json' \
--data '{
   "server_url": "http://your_keycloak_server:8080",
   "realm": "your_realm",
   "client_id": "your_client_id",
   "client_secret": "your_client_secret",
   "user_mapping": {
      "email": "email",
      "family_name": "family_name",
      "given_name": "given_name",
      "id": "sub",
      "name": "preferred_username",
      "roles": "realm_access.roles"
   },
   "permission_mapping": {
      "admin": {
         "AUTH_HANDLER": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "CONVERSATION": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "EMBEDDER": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "LLM": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "MEMORY": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "PLUGINS": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "SETTINGS": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "STATIC": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "STATUS": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "UPLOAD": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
         "USERS": ["WRITE", "EDIT", "LIST", "READ", "DELETE"]
      },
      "user": {
         "CONVERSATION": ["READ", "LIST"],
         "MEMORY": ["READ", "LIST"],
         "STATIC": ["READ"],
         "STATUS": ["READ"]
      }
   }
}'
```


## Usage

Once configured, the Catcloak plugin will automatically handle authentication for your Cheshire Cat instance. Users will need to provide a valid Keycloak JWT token to access protected resources.
