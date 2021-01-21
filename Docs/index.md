## OAuth 2.0 connector

This app contains everything needed to [authenticate a user in the workbench](https://github.com/ExFace/Core/blob/1.x-dev/Docs/Security/Authentication/index.md) or a data connection using the OAuth2 and/or OpenID standards.

The app provides:

- A generic OAuth2 authenticator
- A generic OAuth2 authentication provider for HTTP data connectors
- Traits, interfaces and classes to easily add specific authenticators for different OAuth2 providers

There are also specific authentication implementations for common OAuth providers available as separate apps. Use them if applicable as they require much less configuration!

- [GoogleConnector](https://github.com/axenox/GoogleConnector/blob/master/Docs/index.md)
- [Microsoft365Connector](https://github.com/axenox/Microsoft365Connector/blob/master/Docs/index.md)

Internally the app uses the well known package [PHP League OAuth 2.0 Client](https://oauth2-client.thephpleague.com/).