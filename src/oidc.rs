use crate::env_var;
use crate::route::{AUTH_CALLBACK_PATH, AUTH_LOGIN_PATH};
use crate::user::{UserContext, UserContextTrait};
use crate::{
    route::{auth_callback, auth_login},
    user::{User, UserTokenResponse},
};
use actix_web::http::header;
use actix_web::web::{self};
use actix_web::{HttpRequest, HttpResponse};
use async_trait::async_trait;
use oauth2::http::StatusCode;
use oauth2::url::Url;
use oauth2::{
    AuthorizationCode, ClientId, ConfigurationError, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{
    core::CoreGenderClaim, reqwest::async_http_client, EmptyAdditionalClaims, OAuth2TokenResponse,
    UserInfoClaims,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    IssuerUrl,
};
use openidconnect::{IdTokenVerifier, Nonce};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::collections::HashSet;
use std::env::{self, VarError};
use std::marker::PhantomData;

pub type OidcClient = OidcClientGeneric<UserContext, OidcBffClient>;

impl OidcClient {
    pub async fn setup() -> Result<web::Data<OidcClient>, std::io::Error> {
        OidcBffClient::new()
            .await
            .map(|c| web::Data::new(OidcClient::new(c)))
    }
}

pub struct OidcClientGeneric<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> {
    _p: PhantomData<UC>,
    pub client: OBC,
}

impl<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> OidcClientGeneric<UC, OBC> {
    pub(crate) fn new(client: OBC) -> Self {
        Self {
            _p: PhantomData,
            client,
        }
    }
}

#[async_trait]
pub trait OidcBffClientNonDependentTrait {
    async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<UserTokenResponse, OidcError>;

    fn id_token_verifier(
        &self,
    ) -> IdTokenVerifier<
        '_,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    >;

    fn generate_challenge_response(&self, challenge: PkceCodeChallenge) -> (Url, CsrfToken, Nonce);
}

#[async_trait]
pub trait OidcBffClientTrait<UC: UserContextTrait>: OidcBffClientNonDependentTrait {
    async fn refresh_user(&self, refresh_token: RefreshToken) -> Result<User<UC>, OidcError>;

    async fn user_from_user_info_endpoint_with_token_response(
        &self,
        token_response: UserTokenResponse,
    ) -> Result<User<UC>, OidcError>;
}

pub struct OidcBffClient {
    client: CoreClient,
    scopes: HashSet<Scope>,
}

#[async_trait]
impl OidcBffClientNonDependentTrait for OidcBffClient {
    async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<UserTokenResponse, OidcError> {
        self.client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::ExchangeCode(err.to_string()))
    }

    fn id_token_verifier(
        &self,
    ) -> IdTokenVerifier<
        '_,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
    > {
        self.client.id_token_verifier()
    }

    fn generate_challenge_response(&self, challenge: PkceCodeChallenge) -> (Url, CsrfToken, Nonce) {
        self.client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(self.scopes.clone())
            .set_pkce_challenge(challenge)
            .url()
    }
}

#[async_trait]
impl<UC: UserContextTrait> OidcBffClientTrait<UC> for OidcBffClient {
    async fn refresh_user(&self, refresh_token: RefreshToken) -> Result<User<UC>, OidcError> {
        log::debug!("Starting fetching new token using refresh token.");

        let refresh_token_response = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::FetchingRefreshToken(err.to_string()))?;

        log::debug!("Exchange using refresh token succeeded.");

        self.user_from_user_info_endpoint_with_token_response(refresh_token_response)
            .await
    }

    async fn user_from_user_info_endpoint_with_token_response(
        &self,
        token_response: UserTokenResponse,
    ) -> Result<User<UC>, OidcError> {
        // The user_info request uses the AccessToken returned in the token response. To parse custom
        // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
        // CoreUserInfoClaims type alias.
        log::debug!("fetching user info.");

        let user_info_request = self
            .client
            .user_info(token_response.access_token().to_owned(), None)
            .map_err(OidcError::UserInfoConfiguration)?;

        let user_info: UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim> = user_info_request
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::FetchingUserInfo(err.to_string()))?;

        log::debug!("user info fetched.");

        Ok(User::new(UC::new(user_info, token_response)))
    }
}

impl OidcBffClient {
    const SCOPE_OPENID: &str = "openid";

    fn make_scopes_from_env(env_var_oidc_scopes: Result<String, VarError>) -> HashSet<Scope> {
        let mut scopes = if let Ok(env_scopes) = env_var_oidc_scopes {
            env_scopes
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| Scope::new(s.to_string()))
                .collect()
        } else {
            HashSet::new()
        };
        scopes.insert(Scope::new(OidcBffClient::SCOPE_OPENID.to_string()));
        scopes
    }

    pub async fn new() -> Result<OidcBffClient, std::io::Error> {
        let authority = env::var(env_var::AUTHORITY)
            .unwrap_or_else(|_| panic!("{} must be set", env_var::AUTHORITY));
        let client_id = env::var(env_var::CLIENT_ID)
            .unwrap_or_else(|_| panic!("{} must be set", env_var::CLIENT_ID));
        let redirect_domain_env = env::var(env_var::REDIRECT_DOMAIN)
            .unwrap_or_else(|_| panic!("{} must be set", env_var::REDIRECT_DOMAIN));

        let issuer = IssuerUrl::new(authority)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let redirect_url =
            RedirectUrl::new(format!("{}{}", redirect_domain_env, AUTH_CALLBACK_PATH))
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let client =
            CoreClient::from_provider_metadata(provider_metadata, ClientId::new(client_id), None)
                .set_redirect_uri(redirect_url);

        Ok(OidcBffClient {
            client,
            scopes: OidcBffClient::make_scopes_from_env(env::var(env_var::OIDC_SCOPES)),
        })
    }

    pub fn oidc_web_configurations(cfg: &mut web::ServiceConfig) {
        cfg.service(
            web::scope("/auth")
                .service(auth_callback)
                .service(auth_login),
        );
    }

    pub(crate) fn create_auth_path(req: &HttpRequest) -> String {
        let connection_info = req.connection_info();
        let scheme = connection_info.scheme();
        let host = connection_info.host();

        let domain = format!("{}://{}", scheme, host);

        let path = req.uri().path();
        let query = req.uri().query().unwrap_or("");

        let full_url = if query.is_empty() {
            format!("{}{}", domain, path)
        } else {
            format!("{}{}?{}", domain, path, query)
        };
        let full_url = utf8_percent_encode(&full_url, NON_ALPHANUMERIC).to_string();
        format!("{}{}?path={}", domain, AUTH_LOGIN_PATH, full_url)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OidcError {
    #[error("Not able to exchange code for token: {0}.")]
    ExchangeCode(String),
    #[error("No refresh tokens on claims.")]
    MisingRefreshToken,
    #[error("Issue when fetching refetch token: {0}.")]
    FetchingRefreshToken(String),
    #[error("Configuration error when calling user info.")]
    UserInfoConfiguration(#[source] ConfigurationError),
    #[error("Failed when fetching user info: {0}")]
    FetchingUserInfo(String),
}

impl OidcError {
    pub(crate) fn create_redirect(
        &self,
        req: &HttpRequest,
    ) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let mut builder = HttpResponse::build(StatusCode::TEMPORARY_REDIRECT);
        builder.insert_header((header::LOCATION, OidcBffClient::create_auth_path(req)));
        builder.body(self.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_make_scopes_from_env_with_valid_scopes() {
        // Arrange
        let env_var_oidc_scopes = Ok("profile,email".to_string());

        // Act
        let scopes = OidcBffClient::make_scopes_from_env(env_var_oidc_scopes);

        // Assert
        let mut expected_scopes: HashSet<Scope> = HashSet::new();
        expected_scopes.insert(Scope::new("profile".to_string()));
        expected_scopes.insert(Scope::new("email".to_string()));
        expected_scopes.insert(Scope::new(OidcBffClient::SCOPE_OPENID.to_string()));

        assert_eq!(scopes, expected_scopes);
    }

    #[test]
    fn test_make_scopes_from_env_with_empty_env_var() {
        // Arrange
        let env_var_oidc_scopes = Ok("".to_string());

        // Act
        let scopes = OidcBffClient::make_scopes_from_env(env_var_oidc_scopes);

        // Assert
        let mut expected_scopes: HashSet<Scope> = HashSet::new();
        expected_scopes.insert(Scope::new(OidcBffClient::SCOPE_OPENID.to_string()));

        assert_eq!(scopes, expected_scopes);
    }

    #[test]
    fn test_make_scopes_from_env_with_missing_env_var() {
        // Arrange
        let env_var_oidc_scopes = Err(VarError::NotPresent);

        // Act
        let scopes = OidcBffClient::make_scopes_from_env(env_var_oidc_scopes);

        // Assert
        let mut expected_scopes: HashSet<Scope> = HashSet::new();
        expected_scopes.insert(Scope::new(OidcBffClient::SCOPE_OPENID.to_string()));

        assert_eq!(scopes, expected_scopes);
    }
}
