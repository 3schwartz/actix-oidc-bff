use crate::{
    cookie::{ChunkerError, CookieChunker},
    oidc::OidcBffClient,
    COOKIE_AUTH_USER_PREFIX,
};
use actix_web::{
    cookie::ParseError, http::header, FromRequest, HttpMessage, HttpRequest, HttpResponse,
    ResponseError,
};
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicTokenType, http::StatusCode, EmptyExtraTokenFields, RefreshToken,
    StandardTokenResponse, TokenResponse,
};
use openidconnect::{
    core::{
        CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreUserInfoClaims,
    },
    EmptyAdditionalClaims, IdTokenFields, UserInfoClaims as OidcUserInfoClaims, UserInfoError,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    future::{ready, Ready},
    rc::Rc,
    str::FromStr,
};
use thiserror::Error;

pub(crate) type UserTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EmptyAdditionalClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
    >,
    BasicTokenType,
>;

type UserInfoClaims = OidcUserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>;

pub type OidcAuthenticationState = UserAuthentication<UserContext>;

#[derive(Clone, Debug)]
pub struct UserAuthentication<UC: UserContextTrait> {
    pub user: Rc<User<UC>>,
}

impl<UC: UserContextTrait> From<Rc<User<UC>>> for UserAuthentication<UC> {
    fn from(value: Rc<User<UC>>) -> Self {
        UserAuthentication { user: value }
    }
}

impl<UC: UserContextTrait> UserAuthentication<UC> {
    fn new(user: User<UC>) -> Self {
        Self {
            user: Rc::new(user),
        }
    }
}

impl<UC> FromRequest for UserAuthentication<UC>
where
    UC: UserContextTrait + 'static,
{
    type Error = UserResponseError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        if let Some(user_info) = req.extensions().get::<UserAuthentication<UC>>() {
            let cloned = user_info.clone();
            return ready(Ok(cloned));
        }
        ready(User::try_from(req).map(|user| UserAuthentication::new(user)))
    }
}

pub trait UserContextTrait: Clone + Sync {
    fn new(user_info: UserInfoClaims, token_response: UserTokenResponse) -> Self;
    fn user_info(&self) -> &UserInfoClaims;
    fn token_response(&self) -> &UserTokenResponse;
    fn expires_in(&self) -> Option<core::time::Duration>;
    fn refresh_token(&self) -> Option<RefreshToken>;
    fn from_json(json_value: &Value) -> Result<Self, UserError>;
    fn to_json(&self) -> Result<serde_json::Value, serde_json::Error>;
}

#[derive(Serialize, Clone, Debug)]
pub struct UserContext {
    _user_info: UserInfoClaims,
    _token_response: UserTokenResponse,
}

impl UserContext {
    const USER_INFO_KEY: &'static str = "_user_info";
    const TOKEN_RESPONSE_KEY: &'static str = "_token_response";
}

impl UserContextTrait for UserContext {
    fn new(user_info: UserInfoClaims, token_response: UserTokenResponse) -> Self {
        Self {
            _user_info: user_info,
            _token_response: token_response,
        }
    }

    fn user_info(&self) -> &UserInfoClaims {
        &self._user_info
    }

    fn token_response(&self) -> &UserTokenResponse {
        &self._token_response
    }

    fn expires_in(&self) -> Option<core::time::Duration> {
        self._token_response.expires_in()
    }

    fn from_json(json_value: &Value) -> Result<Self, UserError> {
        let context_info = json_value
            .get(User::<UserContext>::CONTEXT_RESPONSE_KEY)
            .ok_or_else(|| {
                UserError::MissingProperty(User::<UserContext>::CONTEXT_RESPONSE_KEY.to_string())
            })?;

        let user_info = context_info
            .get(Self::USER_INFO_KEY)
            .ok_or_else(|| UserError::MissingProperty(Self::USER_INFO_KEY.to_string()))?;

        let token_response_value = context_info
            .get(Self::TOKEN_RESPONSE_KEY)
            .ok_or_else(|| UserError::MissingProperty(Self::TOKEN_RESPONSE_KEY.to_string()))?;

        let token_response: UserTokenResponse =
            serde_json::from_value(token_response_value.to_owned()).map_err(UserError::from)?;
        let user_info_json = serde_json::to_string(user_info).map_err(UserError::from)?;

        let user_info_mapped = CoreUserInfoClaims::from_json(user_info_json.as_bytes(), None)
            .map_err(UserError::from)?;

        Ok(Self {
            _user_info: user_info_mapped,
            _token_response: token_response,
        })
    }

    fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn refresh_token(&self) -> Option<RefreshToken> {
        self._token_response.refresh_token().cloned()
    }
}

#[derive(Debug)]
pub struct User<UC: UserContextTrait> {
    pub(crate) created: DateTime<Utc>,
    _context: UC,
}

impl<UC: UserContextTrait> User<UC> {
    pub(crate) const CREATED_KEY: &'static str = "_created";
    pub(crate) const CONTEXT_RESPONSE_KEY: &'static str = "_context";

    pub(crate) fn new(context: UC) -> Self {
        Self {
            created: Utc::now(),
            _context: context,
        }
    }

    pub fn user_info(&self) -> &UserInfoClaims {
        self._context.user_info()
    }

    pub fn token_response(&self) -> &UserTokenResponse {
        self._context.token_response()
    }

    pub(crate) fn expires_in(&self) -> Option<core::time::Duration> {
        self._context.expires_in()
    }

    pub(crate) fn refresh_token(&self) -> Option<RefreshToken> {
        self._context.refresh_token()
    }

    pub(crate) fn from_cookies(req: &HttpRequest) -> Result<Self, UserError> {
        let cookies = req.cookies().map_err(UserError::from)?;

        let cookie_chunker = CookieChunker::from_cookies(&cookies, COOKIE_AUTH_USER_PREFIX)?;

        let user_serialized = cookie_chunker.to_string()?;

        let user_state = User::from_str(&user_serialized)?;

        Ok(user_state)
    }
}

impl<UC: UserContextTrait> TryInto<String> for &User<UC> {
    type Error = UserError;

    fn try_into(self) -> Result<String, Self::Error> {
        let _context = self._context.to_json()?;
        let json = json!({ User::<UC>::CREATED_KEY: self.created, User::<UC>::CONTEXT_RESPONSE_KEY: _context });

        Ok(json.to_string())
    }
}

impl<UC: UserContextTrait> TryFrom<&HttpRequest> for User<UC> {
    type Error = UserResponseError;

    fn try_from(value: &HttpRequest) -> Result<Self, Self::Error> {
        match User::<UC>::from_cookies(value) {
            Ok(response) => {
                // When expiry is present check if token has expired and if redirect to auth login.
                if let Some(expiry) = response._context.expires_in() {
                    if Utc::now() > response.created + expiry {
                        return Err(UserResponseError::create_redirect(value));
                    }
                }

                Ok(response)
            }
            Err(err) => match &err {
                UserError::MissingProperty(_)
                | UserError::JsonParse(_)
                | UserError::CookieParse(_)
                | UserError::UserInfo(_) => {
                    log::error!("Not able to authorize due to error {}.", err);
                    Err(UserResponseError::UserError(err))
                }
                UserError::Chunker(_) => {
                    log::debug!(
                        "Not able to get user from cookies redirect to authorize. {}",
                        err
                    );
                    Err(UserResponseError::create_redirect(value))
                }
            },
        }
    }
}

impl<UC: UserContextTrait> FromStr for User<UC> {
    type Err = UserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json_value: Value = serde_json::from_str(s).map_err(UserError::from)?;

        let created_value = json_value
            .get(Self::CREATED_KEY)
            .ok_or_else(|| UserError::MissingProperty(Self::CREATED_KEY.to_string()))?;

        let created: DateTime<Utc> =
            serde_json::from_value(created_value.to_owned()).map_err(UserError::from)?;

        let context = UC::from_json(&json_value)?;

        Ok(Self {
            created,
            _context: context,
        })
    }
}

#[derive(Error, Debug)]
pub enum UserError {
    #[error("{0} missing.")]
    MissingProperty(String),
    #[error("Failed to json parse server response: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Failed to parse cookies: {0}")]
    CookieParse(#[from] ParseError),
    #[error("Failed to map user info: {0}")]
    UserInfo(#[from] UserInfoError<InfoError>),
    #[error("Failed getting cookies: {0}")]
    Chunker(#[from] ChunkerError), // Authorize
}

#[derive(Error, Debug)]
pub enum UserResponseError {
    #[error("Oidc client missing in adapter. Make sure it is registrered.")]
    ClientMissing(),
    #[error("{0}")]
    UserError(#[source] UserError),
    #[error("Redirect to authorization.")]
    Redirect { auth_login_path: String },
}

impl ResponseError for UserResponseError {
    fn status_code(&self) -> oauth2::http::StatusCode {
        match self {
            UserResponseError::ClientMissing() | UserResponseError::UserError(_) => {
                StatusCode::BAD_REQUEST
            }
            UserResponseError::Redirect { .. } => StatusCode::TEMPORARY_REDIRECT,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let mut builder = HttpResponse::build(self.status_code());
        if let UserResponseError::Redirect { auth_login_path } = self {
            builder.insert_header((header::LOCATION, auth_login_path.to_string()));
        };
        builder.body(self.to_string())
    }
}

impl UserResponseError {
    fn create_redirect(req: &HttpRequest) -> UserResponseError {
        UserResponseError::Redirect {
            auth_login_path: OidcBffClient::create_auth_path(req),
        }
    }
}

#[derive(Error, Debug)]
pub enum InfoError {}

#[cfg(test)]
pub(crate) mod test {
    use crate::cookie::CookieCrypto;

    use super::*;
    use actix_web::{cookie::Cookie, test::TestRequest};
    use mockall::mock;
    use serial_test::serial;

    mock! {
            pub UserContextStruct {}

            impl UserContextTrait for UserContextStruct {
                fn new(user_info: UserInfoClaims, token_response: UserTokenResponse) -> Self;
                fn user_info(&self) -> &UserInfoClaims;
                fn token_response(&self) -> &UserTokenResponse;
                fn refresh_token(&self) -> Option<RefreshToken>;
                fn expires_in(&self) -> Option<core::time::Duration>;
                fn from_json(json_value: &Value) -> Result<Self, UserError>;
                fn to_json(&self) -> Result<serde_json::Value, serde_json::Error>;
            }

            impl Clone for UserContextStruct {
                fn clone(&self) -> Self;
            }
    }

    #[test]
    #[serial(from_json_context)]
    fn test_when_user_in_cookies_then_able_to_parse() {
        // Arrange
        let ctx = MockUserContextStruct::from_json_context();
        let expiry = core::time::Duration::from_secs(5);

        ctx.expect().returning(move |_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in().returning(move || Some(expiry));
            Ok(mock)
        });
        let now = Utc::now();
        let json = json!({ User::<MockUserContextStruct>::CREATED_KEY: now, User::<MockUserContextStruct>::CONTEXT_RESPONSE_KEY: "" }).to_string();
        let encrypted = CookieCrypto::encrypt(&json).unwrap();
        let req = TestRequest::default()
            .cookie(Cookie::new(
                format!("{}_1", COOKIE_AUTH_USER_PREFIX),
                encrypted,
            ))
            .to_http_request();

        // Act
        let user_result = User::<MockUserContextStruct>::from_cookies(&req);

        // Assert
        assert!(user_result.is_ok());
        let user = user_result.unwrap();
        assert_eq!(user.created, now);
        assert_eq!(user.expires_in(), Some(expiry));
    }

    #[test]
    fn test_given_errors_when_parse_user_from_cookies_then_error() {
        // Arrange
        let req = TestRequest::default().to_http_request();

        // Act
        let user_result = User::<MockUserContextStruct>::from_cookies(&req);

        // Assert
        assert!(user_result.is_err());
        assert!(matches!(
            user_result,
            Err(UserError::Chunker(ChunkerError::Empty {
                prefix
            })) if prefix == COOKIE_AUTH_USER_PREFIX
        ));
    }
}
