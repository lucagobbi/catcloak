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

Configure the plugin through the Cheshire Cat admin interface or by editing the `settings.json` file:

1. Set up your Keycloak connection details:
   - `server_url`: Your Keycloak server URL
   - `realm`: Your Keycloak realm name
   - `client_id`: Your Keycloak client ID
   - `client_secret`: Your Keycloak client secret

2. Customize the `user_mapping` to map Keycloak user data. You can pass whatever info you want the Cheshire Cat to know about the user.

3. Define the `permission_mapping` to set up role-based access control. If not defined, the user will have the base permissions.

## Usage

Once configured, the Catcloak plugin will automatically handle authentication for your Cheshire Cat instance. Users will need to provide a valid Keycloak JWT token to access protected resources.
