use crate::{
    cookie::CookieChunker,
    oidc::{OidcBffClient, OidcBffClientTrait, OidcClientGeneric, OidcError},
    route::AUTH_SCOPE,
    user::{User, UserAuthentication, UserContext, UserContextTrait},
    COOKIE_AUTH_USER_PREFIX,
};
use actix_web::{
    body::EitherBody,
    cookie::Cookie,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::Data,
    Error, HttpMessage, HttpResponse,
};
use chrono::Utc;
use futures_core::ready as ready_core;
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Future, Ready},
    marker::PhantomData,
    rc::Rc,
    task::Poll,
    time::Duration,
};

pub type OidcAuthorization = OidcAuthorizationGeneric<UserContext>;

impl OidcAuthorization {
    pub fn new() -> Self {
        Self {
            _context: PhantomData,
        }
    }
}

pub struct OidcAuthorizationGeneric<UC: UserContextTrait> {
    _context: PhantomData<UC>,
}

impl<UC: UserContextTrait> Default for OidcAuthorizationGeneric<UC> {
    fn default() -> Self {
        Self {
            _context: PhantomData::<UC>,
        }
    }
}

impl<S, B, UC> Transform<S, ServiceRequest> for OidcAuthorizationGeneric<UC>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    UC: UserContextTrait + 'static,
{
    type Response = ServiceResponse<B>;

    type Error = Error;

    type Transform = OidcAuthorizationMiddleware<S, UC>;

    type InitError = ();

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OidcAuthorizationMiddleware {
            service,
            _context: PhantomData,
        }))
    }
}

pub struct OidcAuthorizationMiddleware<S, UC: UserContextTrait> {
    service: S,
    _context: PhantomData<UC>,
}

impl<S, B, UC> Service<ServiceRequest> for OidcAuthorizationMiddleware<S, UC>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    UC: UserContextTrait + 'static,
{
    type Response = ServiceResponse<B>;

    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let user = req.extract::<UserAuthentication<UC>>();
        let fut = self.service.call(req);
        Box::pin(async move {
            let _ = user.await?;

            let res = fut.await?;
            Ok(res)
        })
    }
}

pub type OidcRefresh = OidcRefreshGeneric<UserContext, OidcBffClient>;

impl OidcRefresh {
    pub fn new() -> Self {
        Self {
            _context: PhantomData,
            _c: PhantomData,
        }
    }
}

pub struct OidcRefreshGeneric<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> {
    _context: PhantomData<UC>,
    _c: PhantomData<OBC>,
}

impl<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> Default for OidcRefreshGeneric<UC, OBC> {
    fn default() -> Self {
        Self {
            _context: PhantomData,
            _c: PhantomData,
        }
    }
}

impl<S, B, UC, OBC> Transform<S, ServiceRequest> for OidcRefreshGeneric<UC, OBC>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    UC: UserContextTrait + 'static,
    OBC: OidcBffClientTrait<UC> + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = OidcRefreshMiddleware<S, UC, OBC>;

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OidcRefreshMiddleware {
            service: Rc::new(service),
            _context: PhantomData,
            _c: PhantomData,
        }))
    }
}

pub struct OidcRefreshMiddleware<S, UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> {
    service: Rc<S>,
    _context: PhantomData<UC>,
    _c: PhantomData<OBC>,
}

impl<S, B, UC, OBC> OidcRefreshMiddleware<S, UC, OBC>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    UC: UserContextTrait + 'static,
    OBC: OidcBffClientTrait<UC> + 'static,
{
    fn refresh_user_cookies(
        user: Rc<User<UC>>,
        mut res: ServiceResponse<B>,
        prior_cookies: Vec<Cookie<'static>>,
    ) -> Result<ServiceResponse<B>, ServiceResponse<EitherBody<B>>> {
        log::debug!("user refreshed so updating oidc cookies.");

        let chunker = match CookieChunker::try_from(user.as_ref()) {
            Ok(chunker) => chunker,
            Err(response) => return Err(res.into_response(response).map_into_right_body()),
        };
        for c in &chunker.cookies {
            match res.response_mut().add_cookie(c) {
                Ok(()) => (),
                Err(err) => {
                    return Err(res
                        .into_response(HttpResponse::InternalServerError().body(err.to_string()))
                        .map_into_right_body())
                }
            }
        }

        let dead_cookies = &chunker.get_dead_cookies(&prior_cookies, COOKIE_AUTH_USER_PREFIX);

        for dead_cookie in dead_cookies {
            match res.response_mut().add_removal_cookie(dead_cookie) {
                Ok(()) => (),
                Err(err) => {
                    return Err(res
                        .into_response(HttpResponse::InternalServerError().body(err.to_string()))
                        .map_into_right_body())
                }
            }
        }

        log::debug!("user oidc cookies updated.");
        Ok(res)
    }
}

impl<S, B, UC, OBC> Service<ServiceRequest> for OidcRefreshMiddleware<S, UC, OBC>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    UC: UserContextTrait + 'static,
    OBC: OidcBffClientTrait<UC> + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;

    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        if req.path().starts_with(AUTH_SCOPE) {
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        let oidc_client = req.app_data::<Data<OidcClientGeneric<UC, OBC>>>();
        if oidc_client.is_none() {
            return Box::pin(ready(Ok(req
                .into_response(
                    HttpResponse::InternalServerError().body("Missing Oidc configurations"),
                )
                .map_into_right_body())));
        }
        let client = oidc_client.unwrap().to_owned();

        let prior_cookies = req
            .request()
            .cookies()
            .map(|c| c.to_vec())
            .unwrap_or_else(|_| Vec::new());

        Box::pin(async move {
            let oidc_extract = OidcRefreshExtract::<UC, OBC>::new(req, client);
            let (request, user_option) = match oidc_extract.await {
                Ok((request, user_option)) => {
                    let user_rc_option = user_option.map(Rc::new);
                    if let Some(user_rc) = &user_rc_option {
                        let cloned = user_rc.clone();
                        request
                            .extensions_mut()
                            .insert(UserAuthentication::from(cloned));
                    }
                    (request, user_rc_option)
                }
                Err((request, err)) => {
                    log::warn!("{}.", err);

                    let response = err.create_redirect(request.request());
                    return Ok(request.into_response(response).map_into_right_body());
                }
            };

            let mut res = service.call(request).await?;

            if let Some(user) = user_option {
                res = match OidcRefreshMiddleware::<S, UC, OBC>::refresh_user_cookies(
                    user,
                    res,
                    prior_cookies,
                ) {
                    Ok(res) => res,
                    Err(err) => return Ok(err),
                };
            };

            Ok(res.map_into_left_body())
        })
    }
}

struct OidcRefreshExtract<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> {
    req: Option<ServiceRequest>,
    client: Data<OidcClientGeneric<UC, OBC>>,
    _future: Option<LocalBoxFuture<'static, Result<Option<User<UC>>, OidcError>>>,
}

impl<UC, OBC> Future for OidcRefreshExtract<UC, OBC>
where
    UC: UserContextTrait + 'static,
    OBC: OidcBffClientTrait<UC> + 'static,
{
    type Output = Result<(ServiceRequest, Option<User<UC>>), (ServiceRequest, OidcError)>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self._future.is_none() {
            let user_result = User::from_cookies(
                self.req
                    .as_mut()
                    .expect(OidcRefreshExtract::<UC, OBC>::FUTURE_POLLED_TWICE)
                    .request(),
            );
            let client = self.client.clone();
            self._future = Some(Box::pin(OidcRefreshExtract::<UC, OBC>::refresh_user(
                client,
                user_result,
            )));
        }
        let fut = self
            ._future
            .as_mut()
            .expect("future should be initialized.");

        let oidc_refresh = ready_core!(fut.as_mut().poll(cx)).map_err(|e| {
            (
                self.req
                    .take()
                    .expect(OidcRefreshExtract::<UC, OBC>::FUTURE_POLLED_TWICE),
                e,
            )
        })?;

        Poll::Ready(Ok((
            self.req
                .take()
                .expect(OidcRefreshExtract::<UC, OBC>::FUTURE_POLLED_TWICE),
            oidc_refresh,
        )))
    }
}

impl<UC: UserContextTrait, OBC: OidcBffClientTrait<UC>> OidcRefreshExtract<UC, OBC> {
    const FUTURE_POLLED_TWICE: &str = "Extract future was polled twice";

    fn new(req: ServiceRequest, client: Data<OidcClientGeneric<UC, OBC>>) -> Self {
        Self {
            req: Some(req),
            client,
            _future: None,
        }
    }

    async fn refresh_user(
        oidc_client: Data<OidcClientGeneric<UC, OBC>>,
        user_result: Result<User<UC>, crate::user::UserError>,
    ) -> Result<Option<User<UC>>, OidcError> {
        if user_result.is_err() {
            return Ok(None);
        }
        let user: User<UC> = user_result.unwrap();
        if user.expires_in().is_none() {
            log::debug!("user token doesn't have expiry.");
            return Ok(None);
        }
        let expiry: Duration = user.expires_in().unwrap();
        if Utc::now() < user.created + expiry {
            log::debug!("user token still valid");
            return Ok(None);
        }
        let refresh_token = user.refresh_token();
        if refresh_token.is_none() {
            log::debug!(
                "user token has expired but no refresh token exists. Redirecting to login."
            );
            return Err(OidcError::MisingRefreshToken);
        };

        oidc_client
            .client
            .refresh_user(refresh_token.unwrap())
            .await
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookie::CookieCrypto;
    use crate::user::UserContextTrait;
    use crate::{oidc::OidcBffClientNonDependentTrait, user::test::MockUserContextStruct};
    use actix_web::{test, web, App};
    use async_trait::async_trait;
    use mockall::mock;
    use oauth2::http::StatusCode;
    use oauth2::RefreshToken;
    use serde_json::json;
    use serial_test::serial;

    mock! {
        pub OidcBffClientStruct<UC: UserContextTrait> {}

        #[async_trait]
        impl<UC: UserContextTrait> OidcBffClientTrait<UC> for OidcBffClientStruct<UC> {
            async fn refresh_user(&self, refresh_token: oauth2::RefreshToken) -> Result<User<UC>, OidcError>;

            async fn user_from_user_info_endpoint_with_token_response(
            &self,
            token_response: crate::user::UserTokenResponse,
            ) -> Result<User<UC>, OidcError>;
        }

        #[async_trait]
        impl<UC: UserContextTrait> OidcBffClientNonDependentTrait for OidcBffClientStruct<UC> {
            async fn exchange_code(
                &self,
                code: String,
                pkce_verifier: String,
            ) -> Result<crate::user::UserTokenResponse, OidcError>;

            fn id_token_verifier(
                &self,
            ) -> openidconnect::IdTokenVerifier<'static,openidconnect::core::CoreJwsSigningAlgorithm,openidconnect::core::CoreJsonWebKeyType,openidconnect::core::CoreJsonWebKeyUse,openidconnect::core::CoreJsonWebKey, > ;

            fn generate_challenge_response(&self, challenge: oauth2::PkceCodeChallenge) -> (oauth2::url::Url, oauth2::CsrfToken, openidconnect::Nonce);
        }
    }

    fn create_user_cookie() -> Cookie<'static> {
        let json = json!({ User::<MockUserContextStruct>::CREATED_KEY: Utc::now(), User::<MockUserContextStruct>::CONTEXT_RESPONSE_KEY: "" }).to_string();
        let encrypted = CookieCrypto::encrypt(&json).unwrap();
        Cookie::new(format!("{}_1", COOKIE_AUTH_USER_PREFIX), encrypted)
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_token_not_expired_when_refresh_then_return_ok_with_no_updated_cookies() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in()
                .returning(|| Some(core::time::Duration::from_secs(5)));
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        let response = resp.response().to_owned();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.cookies().count(), 0)
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_no_expiry_when_refresh_then_return_ok_with_no_updated_cookies() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in().returning(|| None);
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        let response = resp.response().to_owned();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.cookies().count(), 0)
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_expired_and_refesh_token_when_refresh_then_update_cookies() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in()
                .returning(|| Some(core::time::Duration::from_secs(0)));
            mock.expect_refresh_token()
                .returning(|| Some(RefreshToken::new("hello".to_string())));
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mut mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let mut user_context_mock_updated = MockUserContextStruct::default();
        user_context_mock_updated
            .expect_to_json()
            .times(1)
            .return_once(|| Ok(serde_json::Value::String("".to_string())));
        let new_user = User::new(user_context_mock_updated);
        mock_client
            .expect_refresh_user()
            .times(1)
            .return_once(|_| Ok(new_user));

        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        let response = resp.response().to_owned();
        assert_eq!(response.cookies().count(), 1);
        assert!(response
            .cookies()
            .any(|c| c.name().eq(&format!("{}_1", COOKIE_AUTH_USER_PREFIX))))
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_expired_and_no_refesh_token_when_refresh_then_redirect() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in()
                .returning(|| Some(core::time::Duration::from_secs(0)));
            mock.expect_refresh_token().returning(|| None);
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_expired_and_no_refesh_token_when_refresh_on_auth_scope_then_ok() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in()
                .returning(|| Some(core::time::Duration::from_secs(0)));
            mock.expect_refresh_token().returning(|| None);
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route(AUTH_SCOPE, web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri(AUTH_SCOPE)
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_refresh_token_error_when_refersh_then_redirect() {
        // Arrange
        // setup user context mock
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(|_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in()
                .returning(|| Some(core::time::Duration::from_secs(0)));
            mock.expect_refresh_token()
                .returning(|| Some(RefreshToken::new("hello".to_string())));
            Ok(mock)
        });

        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mut mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        mock_client
            .expect_refresh_user()
            .times(1)
            .return_once(|_| Err(OidcError::FetchingRefreshToken("SomeError".to_string())));

        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[actix_web::test]
    async fn given_user_error_when_refersh_then_return_ok() {
        // Arrange
        // setup application with middleware and oidc client mock
        let middleware = OidcRefreshGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::default();
        let mock_client = MockOidcBffClientStruct::<MockUserContextStruct>::default();
        let client = OidcClientGeneric::<
            MockUserContextStruct,
            MockOidcBffClientStruct<MockUserContextStruct>,
        >::new(mock_client);

        let srv = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make request
        let req = test::TestRequest::with_uri("/").to_request();

        // Act
        let resp = srv.call(req).await.unwrap();

        // Assert
        let response = resp.response().to_owned();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.cookies().count(), 0)
    }

    #[actix_web::test]
    async fn given_user_authentication_extension_when_authorize_then_return_ok() {
        // Arrange
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        req.extensions_mut()
            .insert(UserAuthentication::from(Rc::new(User::new(
                MockUserContextStruct::default(),
            ))));

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().status(), StatusCode::OK);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_no_expiry_in_when_user_from_cookies_then_return_ok() {
        // Arrange
        let ctx = MockUserContextStruct::from_json_context();
        ctx.expect().returning(move |_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in().returning(move || None);
            Ok(mock)
        });
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().status(), StatusCode::OK);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_expired_token_when_user_from_cookies_then_return_redirect() {
        // Arrange
        let ctx = MockUserContextStruct::from_json_context();
        let expiry = core::time::Duration::from_secs(0);
        ctx.expect().returning(move |_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in().returning(move || Some(expiry));
            Ok(mock)
        });
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let req = test::TestRequest::with_uri("/")
            .cookie(create_user_cookie())
            .to_request();

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_err());
        let error = resp.unwrap_err();
        let error_response = error.error_response();
        assert_eq!(error_response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_non_expired_token_when_user_present_then_return_ok() {
        // Arrange
        let ctx = MockUserContextStruct::from_json_context();
        let expiry = core::time::Duration::from_secs(5);
        ctx.expect().returning(move |_| {
            let mut mock = MockUserContextStruct::default();
            mock.expect_expires_in().returning(move || Some(expiry));
            Ok(mock)
        });
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let now = Utc::now();
        let json = json!({ User::<MockUserContextStruct>::CREATED_KEY: now, User::<MockUserContextStruct>::CONTEXT_RESPONSE_KEY: "" }).to_string();
        let encrypted = CookieCrypto::encrypt(&json).unwrap();
        let cookie = Cookie::new(format!("{}_1", COOKIE_AUTH_USER_PREFIX), encrypted);

        let req = test::TestRequest::with_uri("/").cookie(cookie).to_request();

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn given_no_user_then_return_redirect() {
        // Arrange
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let req = test::TestRequest::with_uri("/").to_request();

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_err());
        let error = resp.unwrap_err();
        let error_response = error.error_response();
        assert_eq!(error_response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[actix_web::test]
    #[serial(from_json_context)]
    async fn given_error_when_decrypt_when_authorize_then_redirect() {
        // Arrange
        let middleware = OidcAuthorizationGeneric::<MockUserContextStruct>::default();
        let srv = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/", web::get().to(HttpResponse::Ok)),
        )
        .await;

        // make user cookie
        let cookie = Cookie::new(format!("{}_1", COOKIE_AUTH_USER_PREFIX), "not good");
        // make request
        let req = test::TestRequest::with_uri("/").cookie(cookie).to_request();

        // Act
        let resp = srv.call(req).await;

        // Assert
        assert!(resp.is_err());
        let error = resp.unwrap_err();
        let error_response = error.error_response();
        assert_eq!(error_response.status(), StatusCode::TEMPORARY_REDIRECT);
    }
}
