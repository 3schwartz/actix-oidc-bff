#![allow(rustdoc::invalid_rust_codeblocks)]
#![doc = r#"
# actix-oidc-bff

A comprehensive Backend For Frontend (BFF) OIDC solution for the [Actix web framework](Actix web framework), designed for secure and easy OIDC integration.

actix-oidc-bff provides a robust way to handle OIDC flows server-side, managing token exchanges, refresh tokens, and retrieving user data without exposing tokens to clients. It offers flexibility to enforce authentication at specific endpoints or across service scopes. It automatically handles initiating OIDC flows, including PKCE and callbacks.

This solution is powered by the excellent [openidconnect](https://docs.rs/openidconnect) crate – special thanks to its contributors.

# Getting started

To begin using `actix-oidc-bff`, let’s look at a simple Actix web application example:

```rust,ignore
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

```rust,ignore
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
```rust,ignore
#[get("/using-context")]
async fn using_context(_: HttpRequest, user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Hey there!")
}
```

This requires the user to be authenticated and provides access to user data via `OidcAuthenticationState`.

### Scope-Wide Authentication

To require authentication for an entire scope, use the `OidcAuthorization` middleware:
```rust,ignore
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

```rust,ignore
#[get("/with-middleware")]
async fn with_middleware(user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Here authentication is needed.")
}
```
"#]

pub(crate) mod cookie;
pub(crate) mod env_var;
pub mod middleware;
pub mod oidc;
pub(crate) mod route;
pub(crate) mod types;
pub mod user;

const COOKIE_AUTH_CHALLENGE_STATE_PREFIX: &str = "oidc_challenge_";
const COOKIE_AUTH_USER_PREFIX: &str = "oidc_user_";
