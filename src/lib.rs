pub(crate) mod cookie;
pub(crate) mod env_var;
pub mod middleware;
pub mod oidc;
pub(crate) mod route;
pub(crate) mod types;
pub mod user;

const COOKIE_AUTH_CHALLENGE_STATE_PREFIX: &str = "oidc_challenge_";
const COOKIE_AUTH_USER_PREFIX: &str = "oidc_user_";
