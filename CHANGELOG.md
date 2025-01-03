# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of `actix-oidc-bff`.
- Middleware for OIDC authorization (`OidcAuthorization`) and token refresh (`OidcRefresh`).
- User authentication context (`OidcAuthenticationState`) for secure access to user data.
- Full support for OIDC flows, including login, token refresh, and user session management.
- Encrypted cookies for secure storage of authentication state.
- Configuration helpers for OIDC client setup via environment variables.
- Example Actix Web application demonstrating library usage.
