use actix_web::{
    cookie::Expiration, get, http::header, web, HttpRequest, HttpResponse, HttpResponseBuilder,
    Responder,
};
use openidconnect::{
    AccessTokenHash, Nonce, OAuth2TokenResponse, PkceCodeChallenge, TokenResponse,
};
use percent_encoding::percent_decode_str;

use crate::{
    cookie::{CookieChunker, CookieHelper, CookiePath},
    oidc::{OidcBffClientNonDependentTrait, OidcBffClientTrait, OidcClient},
    types::{AuthCallbackParams, AuthLoginParams, ChallengeState},
    user::{User, UserContext, UserTokenResponse},
    COOKIE_AUTH_CHALLENGE_STATE_PREFIX,
};

pub(crate) const AUTH_SCOPE: &str = "/auth";
pub(crate) const AUTH_LOGIN_PATH: &str = "/auth/login";
pub(crate) const AUTH_CALLBACK_PATH: &str = "/auth/callback";

#[get("/callback")]
pub(crate) async fn auth_callback(
    req: HttpRequest,
    params: web::Query<AuthCallbackParams>,
    client: web::Data<OidcClient>,
) -> impl Responder {
    if let Some(error) = &params.error {
        if let Some(description) = &params.error_description {
            return HttpResponse::InternalServerError().body(description.clone());
        }
        return HttpResponse::InternalServerError().body(error.to_owned());
    }
    let code = &params.code;

    let cookies = match req.cookies() {
        Ok(cookies) => cookies.to_vec(),
        Err(err) => return HttpResponse::InternalServerError().body(err.as_str()),
    };

    let cookie_chunker =
        match CookieChunker::from_cookies(&cookies, COOKIE_AUTH_CHALLENGE_STATE_PREFIX) {
            Ok(cookie_chunker) => cookie_chunker,
            Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
        };

    let challenge_state_serialized = match cookie_chunker.to_string() {
        Ok(challenge_state_serialized) => challenge_state_serialized,
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    let challenge_state: ChallengeState =
        match serde_json::from_str::<ChallengeState>(&challenge_state_serialized) {
            Ok(challenge_state) => challenge_state,
            Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
        };

    if challenge_state.csrf_token != params.state {
        return HttpResponse::InternalServerError().body("CSRF token doesn't match.");
    }

    let token_response = match client
        .client
        .exchange_code(code.to_owned(), challenge_state.pkce_verifier)
        .await
    {
        Ok(token_response) => token_response,
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    let id_token = match token_response.id_token() {
        Some(id_token) => id_token,
        None => {
            return HttpResponse::InternalServerError().body("Server did not return an ID token")
        }
    };
    let claims = match id_token.claims(
        &client.client.id_token_verifier(),
        &Nonce::new(challenge_state.nonce),
    ) {
        Ok(claims) => claims,
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let signing_alg = match id_token.signing_alg() {
            Ok(signing_alg) => signing_alg,
            Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
        };
        let actual_access_token_hash =
            match AccessTokenHash::from_token(token_response.access_token(), &signing_alg) {
                Ok(actual_access_token_hash) => actual_access_token_hash,
                Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
            };
        if actual_access_token_hash != *expected_access_token_hash {
            return HttpResponse::InternalServerError().body("Invalid access token");
        }
    } else {
        return HttpResponse::BadRequest().body("Access token hash is missing.".to_string());
    }

    let mut http_response_builder = match generate_user_from_user_info_endpoint_with_token_response(
        client,
        token_response,
        challenge_state.path.to_string(),
    )
    .await
    {
        Ok(builder) => builder,
        Err(err) => return err,
    };

    CookieHelper::remove_challenge_cookies(&req, &mut http_response_builder);

    http_response_builder.finish()
}

#[get("/login")]
pub(crate) async fn auth_login(
    req: HttpRequest,
    params: web::Query<AuthLoginParams>,
    client: web::Data<OidcClient>,
) -> impl Responder {
    let path = match &params.path {
        Some(path) => path.to_string(),
        None => {
            let connection_info = req.connection_info();
            let scheme = connection_info.scheme();
            let host = connection_info.host();
            format!("{}://{}", scheme, host)
        }
    };
    let path = match percent_decode_str(&path).decode_utf8() {
        Ok(path) => path.to_string(),
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client.client.generate_challenge_response(pkce_challenge);

    let auth_state = ChallengeState::new(pkce_verifier, csrf_token, nonce, path);
    let auth_state_serialized = match serde_json::to_string(&auth_state) {
        Ok(auth_state_serialized) => auth_state_serialized,
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    let chunker = match CookieChunker::from_string(
        &auth_state_serialized,
        COOKIE_AUTH_CHALLENGE_STATE_PREFIX,
        Expiration::Session,
        CookiePath::Callback,
    ) {
        Ok(chunker) => chunker,
        Err(err) => return HttpResponse::InternalServerError().body(err.to_string()),
    };

    let mut response = HttpResponse::TemporaryRedirect();
    for c in chunker.cookies {
        response.cookie(c);
    }

    CookieHelper::remove_auth_cookies(&req, &mut response);

    response
        .append_header((header::LOCATION, auth_url.to_string()))
        .finish()
}

async fn generate_user_from_user_info_endpoint_with_token_response(
    client: web::Data<OidcClient>,
    token_response: UserTokenResponse,
    path: String,
) -> Result<HttpResponseBuilder, HttpResponse> {
    let user: User<UserContext> = match client
        .client
        .user_from_user_info_endpoint_with_token_response(token_response)
        .await
    {
        Ok(user) => user,
        Err(err) => return Err(HttpResponse::InternalServerError().body(err.to_string())),
    };
    let chunker = match CookieChunker::try_from(&user) {
        Ok(chunker) => chunker,
        Err(response) => return Err(response),
    };

    let mut response = HttpResponse::TemporaryRedirect();
    for c in chunker.cookies {
        response.cookie(c);
    }

    response.append_header((header::LOCATION, path));
    Ok(response)
}
