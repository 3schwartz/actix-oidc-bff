[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B49102%2Fgithub.com%2F3schwartz%2Factix-oidc-bff.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B49102%2Fgithub.com%2F3schwartz%2Factix-oidc-bff?ref=badge_shield&issueType=license)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B49102%2Fgithub.com%2F3schwartz%2Factix-oidc-bff.svg?type=shield&issueType=security)](https://app.fossa.com/projects/custom%2B49102%2Fgithub.com%2F3schwartz%2Factix-oidc-bff?ref=badge_shield&issueType=security)

# actix-oidc-bff

A comprehensive Backend For Frontend (BFF) OIDC solution for the [Actix web framework](Actix web framework), designed for secure and easy OIDC integration.

actix-oidc-bff provides a robust way to handle OIDC flows server-side, managing token exchanges, refresh tokens, and retrieving user data without exposing tokens to clients. It offers flexibility to enforce authentication at specific endpoints or across service scopes. It automatically handles initiating OIDC flows, including PKCE and callbacks.

This solution is powered by the excellent [openidconnect](https://docs.rs/openidconnect) crate – special thanks to its contributors.

# Getting started

To begin using `actix-oidc-bff`, let’s look at a simple Actix web application example:

```rust
use actix_oidc_bff::{
    middleware::{OidcAuthorization, OidcRefresh},
    oidc::{OidcBffClient, OidcClient},
    user::OidcAuthenticationState,
};
use actix_web::{
    get,
    web::{self},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use dotenv::dotenv;
use env_logger::Env;

#[get("/without-middleware")]
async fn without_middleware() -> impl Responder {
    HttpResponse::Ok().body("I can always be called.")
}

#[get("/with-middleware")]
async fn with_middleware() -> impl Responder {
    HttpResponse::Ok().body("Here authentication is needed.")
}

#[get("/using-context")]
async fn using_context(_: HttpRequest, user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Initiliaze the OIDC client
    let oidc_client = OidcClient::setup().await?;

    HttpServer::new(move || {
        App::new()
            // Register the OIDC client as app data such that it is available for middleware.
            .app_data(oidc_client.clone())
            // Register auth routes
            .configure(OidcBffClient::oidc_web_configurations)
            // Register refresh middleware
            .wrap(OidcRefresh::new())
            .service(without_middleware)
            .service(using_context)
            .service(
                web::scope("with")
                    // Register authorization middleware
                    .wrap(OidcAuthorization::default())
                    .service(with_middleware),
            )
    })
    .bind(("127.0.0.1", 8123))?
    .run()
    .await
}
```

## Initialization

To set up `actix-oidc-bff`, follow these steps:

- Initialize the OIDC client and register it as app data.
- Register the login and callback routes within the `/auth` scope.
- Register the refresh middleware to handle token refreshing and user information updates.

```rust
    // Initialize the OIDC client
    let oidc_client = OidcClient::setup().await?;

    HttpServer::new(move || {
        App::new()
            // Register the OIDC client as app data, making it available for middleware.
            .app_data(oidc_client.clone())
            // Register authentication routes
            .configure(OidcBffClient::oidc_web_configurations)
            // Register refresh middleware
            .wrap(OidcRefresh::new())
...            
```

## Adding Authentication

There are two ways to add authentication. 

Unauthenticated users attempting to access routes protected by either `OidcAuthenticationState` or the `OidcAuthorization` middleware will be automatically redirected to begin the OIDC login flow.

### Single-Service Authentication

To enforce authentication on a specific service, add `OidcAuthenticationState` as a parameter to the service.
```rust
#[get("/using-context")]
async fn using_context(_: HttpRequest, user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Hey there!")
}
```

This requires the user to be authenticated and provides access to user data via `OidcAuthenticationState`.

### Scope-Wide Authentication

To require authentication for an entire scope, use the `OidcAuthorization` middleware:
```rust
..
#[get("/with-middleware")]
async fn with_middleware() -> impl Responder {
    HttpResponse::Ok().body("Here authentication is needed.")
}
..
            .service(
                web::scope("with")
                    // Register auth middleware
                    .wrap(OidcAuthorization::default())
                    .service(with_middleware),
            )
..
```

When using middleware for a scope, you don’t need to add `OidcAuthenticationState` as a parameter. However, if the service needs access to user data, you can still include it as a parameter:

```rust
#[get("/with-middleware")]
async fn with_middleware(user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Here authentication is needed.")
}
```

# Configurations

Configuration settings are managed through environment variables.

| Name                  | Description                                                                                                                                                                                  | Default            | Mandatory | Examples                               |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|-----------|----------------------------------------|
| AUTHORITY             | The URL of the Identity Provider (IdP).                                                                                                                                                      | -                  | Yes       | `https://some-idp-example.com`         |
| CLIENT_ID             | Client ID used by the frontend application.                                                                                                                                                  | -                  | Yes       | `34d7de69-5113-438e-8123-4d0449baebc1` |
| REDIRECT_DOMAIN       | Domain where this service is accessible. `/auth/callback` will be appended to form the final callback URL.                                                                                   | -                  | Yes       | `https://some-domain-example.com`      |
| OIDC_SCOPES           | Comma-separated list of scopes; the `openid` scope is always included.                                                                                                                       | `openid`           | Yes       | `openid,email,offline_access`          |
| ENCRYPTION_KEY        | Key for AES256-GCM encryption of cookies. If unset, a random key is generated, requiring users to re-authenticate after each application restart. For distributed systems, use a shared key. | Randomly generated | Yes       | `abcdefghijklmnopqrstuvwxyz123456`     |
| USER_LIFETIME_SECONDS | Lifetime of cookies in seconds, ideally matching the refresh token lifespan. Defaults to 3 days.                                                                                             | `259.200`          | Yes       | `259.200`                              |
