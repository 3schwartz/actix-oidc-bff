use oauth2::{CsrfToken, PkceCodeVerifier};
use openidconnect::Nonce;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) struct ChallengeState {
    pub(crate) pkce_verifier: String,
    pub(crate) csrf_token: String,
    pub(crate) nonce: String,
    pub(crate) path: String,
}

impl ChallengeState {
    pub(crate) fn new(
        pkce_verifier: PkceCodeVerifier,
        csrf_token: CsrfToken,
        nonce: Nonce,
        path: String,
    ) -> Self {
        Self {
            pkce_verifier: pkce_verifier.secret().to_owned(),
            csrf_token: csrf_token.secret().to_owned(),
            nonce: nonce.secret().to_owned(),
            path,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct AuthCallbackParams {
    pub(crate) code: String,
    pub(crate) state: String,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AuthLoginParams {
    pub(crate) path: Option<String>,
}
