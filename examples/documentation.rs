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

#[get("/using-state")]
async fn using_state(_: HttpRequest, user_state: OidcAuthenticationState) -> impl Responder {
    println!("{:?}", user_state.user);

    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(Env::default().default_filter_or("info"));

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
            .service(without_middleware)
            .service(using_state)
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
