use crate::{
    env_var,
    route::AUTH_CALLBACK_PATH,
    user::{User, UserContextTrait},
    COOKIE_AUTH_CHALLENGE_STATE_PREFIX, COOKIE_AUTH_USER_PREFIX,
};
use actix_web::{
    cookie::{
        time::{Duration, OffsetDateTime},
        Cookie, Expiration,
    },
    HttpRequest, HttpResponse, HttpResponseBuilder,
};
use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
use hex::FromHexError;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    env,
    string::FromUtf8Error,
    sync::RwLock,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChunkerError {
    #[error("No cookies found which matched {prefix:?}")]
    Empty { prefix: String },
    #[error("Invalid slice occurred during cookie creation")]
    InvalidSlice,
    #[error("Not all cookies had common prefix {prefix:?}")]
    PrefixNotConsistent { prefix: String },
    #[error("Not able to get part number from cookie name: {cookie_name:?}")]
    InvalidPartNumber { cookie_name: String },
    #[error("Issue when getting lock: {0}")]
    Lock(String),
    #[error("key length must be either 32 og 64 char long")]
    AesKey,
    #[error("{0}")]
    AesGcm(String),
    #[error("{0}")]
    HexDecode(#[from] FromHexError),
    #[error("{0}")]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl From<aes_gcm::aead::Error> for ChunkerError {
    fn from(value: aes_gcm::aead::Error) -> Self {
        ChunkerError::AesGcm(value.to_string())
    }
}

pub(crate) struct CookieChunker<'a> {
    cookie_name_prefix: &'a str,
    pub(crate) cookies: Vec<Cookie<'a>>,
}

impl<'a, UC: UserContextTrait> TryFrom<&User<UC>> for CookieChunker<'a> {
    type Error = HttpResponse;

    fn try_from(value: &User<UC>) -> Result<Self, Self::Error> {
        let duration = env::var(env_var::USER_LIFETIME_SECONDS)
            .ok()
            .and_then(|e| e.parse::<i64>().ok())
            .map_or_else(
                || Duration::seconds(CookieChunker::DEFAULT_USER_LIFETIME_SECONDS),
                Duration::seconds,
            );

        let user_state_serialized: String = match value.try_into() {
            Ok(user_state_serialized) => user_state_serialized,
            Err(err) => return Err(HttpResponse::InternalServerError().body(err.to_string())),
        };
        let chunker = match CookieChunker::from_string(
            &user_state_serialized,
            COOKIE_AUTH_USER_PREFIX,
            Expiration::DateTime(OffsetDateTime::now_utc().saturating_add(duration)),
            CookiePath::All,
        ) {
            Ok(chunker) => chunker,
            Err(err) => return Err(HttpResponse::InternalServerError().body(err.to_string())),
        };
        Ok(chunker)
    }
}

pub(crate) enum CookiePath {
    All,
    Callback,
}

impl CookiePath {
    const ALL_PATH: &'static str = "/";
}

impl<'c> From<&CookiePath> for Cow<'c, str> {
    fn from(val: &CookiePath) -> Self {
        match val {
            CookiePath::All => Cow::Owned(CookiePath::ALL_PATH.to_string()),
            CookiePath::Callback => Cow::Owned(AUTH_CALLBACK_PATH.to_string()),
        }
    }
}

impl<'a> CookieChunker<'a> {
    const MAX_SIZE: usize = 3_500;
    const DEFAULT_USER_LIFETIME_SECONDS: i64 = 60 * 60 * 24 * 3;

    pub(crate) fn get_dead_cookies(
        &self,
        cookies: &'a [Cookie],
        cookie_name_prefix: &str,
    ) -> Vec<Cookie> {
        let chuncker_cookie_names: HashSet<&str> = self.cookies.iter().map(|c| c.name()).collect();

        cookies
            .iter()
            .filter(|cookie| cookie.name().starts_with(cookie_name_prefix))
            .filter(|cookie| !chuncker_cookie_names.contains(cookie.name()))
            .cloned()
            .collect()
    }

    pub(crate) fn from_cookies(
        cookies: &'a [Cookie],
        cookie_name_prefix: &'a str,
    ) -> Result<Self, ChunkerError> {
        let matching_cookies: Vec<Cookie> = cookies
            .iter()
            .filter(|cookie| cookie.name().starts_with(cookie_name_prefix))
            .cloned()
            .collect();

        if matching_cookies.is_empty() {
            return Err(ChunkerError::Empty {
                prefix: cookie_name_prefix.to_string(),
            });
        };

        Ok(Self {
            cookies: matching_cookies,
            cookie_name_prefix,
        })
    }

    pub(crate) fn to_string(&self) -> Result<String, ChunkerError> {
        let mut parts: BTreeMap<usize, &str> = BTreeMap::new();

        for cookie in &self.cookies {
            match Self::extract_part_number(cookie.name(), self.cookie_name_prefix) {
                Ok(part_number) => {
                    parts.insert(part_number, cookie.value());
                }
                Err(err) => return Err(err),
            }
        }

        let encrypted = parts.values().cloned().collect::<Vec<_>>().concat();
        CookieCrypto::decrypt(&encrypted)
    }

    pub(crate) fn from_string(
        long_string: &str,
        cookie_name_prefix: &'a str,
        expiry: Expiration,
        path: CookiePath,
    ) -> Result<Self, ChunkerError> {
        let encrypted = CookieCrypto::encrypt(long_string)?;

        Self::from_string_with_size(&encrypted, cookie_name_prefix, Self::MAX_SIZE, expiry, path)
    }

    fn from_string_with_size(
        long_string: &str,
        cookie_name_prefix: &'a str,
        max_cookie_size: usize,
        expiry: Expiration,
        path: CookiePath,
    ) -> Result<Self, ChunkerError> {
        let byte_string = long_string.as_bytes();
        let mut cookies: Vec<Cookie> = Vec::new();
        let mut part_number = 1;
        let mut start_index = 0;

        while start_index < byte_string.len() {
            let mut end_index = start_index + max_cookie_size;

            if end_index > byte_string.len() {
                end_index = byte_string.len();
            } else {
                // Ensure we do not split in the middle of a multibyte character
                while end_index > start_index
                    && !byte_string[end_index].is_ascii()
                    && (byte_string[end_index] & 0b1100_0000) == 0b1000_0000
                {
                    end_index -= 1;
                }
            }

            if end_index <= start_index {
                return Err(ChunkerError::InvalidSlice);
            }

            let chunk = &long_string[start_index..end_index];

            let cookie_name = format!("{}_{}", cookie_name_prefix, part_number);

            let cookie = Cookie::build(cookie_name, chunk.to_string())
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .expires(expiry)
                .secure(true)
                .path(&path)
                .finish();

            cookies.push(cookie);

            start_index = end_index;
            part_number += 1;
        }

        Ok(Self {
            cookies,
            cookie_name_prefix,
        })
    }

    fn extract_part_number(cookie_name: &str, prefix: &str) -> Result<usize, ChunkerError> {
        if let Some(suffix) = cookie_name.strip_prefix(prefix) {
            if let Ok(part) = suffix.trim_start_matches('_').parse::<usize>() {
                return Ok(part);
            }
        }
        Err(ChunkerError::InvalidPartNumber {
            cookie_name: String::from(cookie_name),
        })
    }
}

pub(crate) struct CookieHelper {}

impl CookieHelper {
    pub(crate) fn remove_challenge_cookies(req: &HttpRequest, response: &mut HttpResponseBuilder) {
        Self::remove_cookies(
            req,
            response,
            COOKIE_AUTH_CHALLENGE_STATE_PREFIX,
            CookiePath::Callback,
        );
    }

    pub(crate) fn remove_auth_cookies(req: &HttpRequest, response: &mut HttpResponseBuilder) {
        Self::remove_cookies(req, response, COOKIE_AUTH_USER_PREFIX, CookiePath::All);
    }

    fn remove_cookies(
        req: &HttpRequest,
        response: &mut HttpResponseBuilder,
        prefix: &str,
        path: CookiePath,
    ) {
        let dead_cookies = req
            .cookies()
            .map(|cookies| {
                cookies
                    .iter()
                    .filter(|cookie| cookie.name().starts_with(prefix))
                    .cloned()
                    .collect::<Vec<Cookie>>()
            })
            .unwrap_or_default();

        for mut dead_cookie in dead_cookies {
            dead_cookie.make_removal();
            dead_cookie.set_path(&path);
            response.cookie(dead_cookie);
        }
    }
}

pub(crate) struct CookieCrypto {}

static _KEY: RwLock<Option<String>> = RwLock::new(None);
impl CookieCrypto {
    fn get_key() -> Result<Vec<u8>, ChunkerError> {
        {
            let key_option = _KEY.read().map_err(|e| ChunkerError::Lock(e.to_string()))?;
            if let Some(key) = key_option.as_ref() {
                return hex::decode(key).map_err(ChunkerError::HexDecode);
            }
        }

        let mut key_option = _KEY
            .write()
            .map_err(|e| ChunkerError::Lock(e.to_string()))?;

        if let Some(key) = key_option.as_ref() {
            return hex::decode(key).map_err(ChunkerError::HexDecode);
        }

        let env_key = env::var(env_var::ENCRYPTION_KEY)
            .map(hex::encode)
            .unwrap_or_else(|_| hex::encode(Aes256Gcm::generate_key(&mut OsRng)));
        let key_size = env_key.chars().count();
        // saved as hex and hence length is 64 for 32 byte key
        if key_size != 64 {
            return Err(ChunkerError::AesKey);
        }

        *key_option = Some(env_key.to_string());
        hex::decode(env_key).map_err(ChunkerError::HexDecode)
    }

    pub(crate) fn encrypt(plaintext: &str) -> Result<String, ChunkerError> {
        let stored_key = CookieCrypto::get_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&stored_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(key);

        let ciphered_data = cipher.encrypt(&nonce, plaintext.as_bytes())?;

        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphered_data);
        Ok(hex::encode(encrypted_data))
    }

    pub(crate) fn decrypt(plaintext: &str) -> Result<String, ChunkerError> {
        let stored_key = CookieCrypto::get_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&stored_key);

        let encrypted_data = hex::decode(plaintext)?;

        let (nonce_vec, ciphered_text) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_vec);

        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher.decrypt(nonce, ciphered_text)?;

        String::from_utf8(plaintext).map_err(ChunkerError::FromUtf8Error)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{cookie::SameSite, http::header, test::TestRequest};

    #[test]
    fn test_remove_auth_cookies() {
        // Create a TestRequest with some cookies
        let req = TestRequest::default()
            .cookie(Cookie::new(
                format!("{}_1", COOKIE_AUTH_USER_PREFIX),
                "value1",
            ))
            .cookie(Cookie::new(
                format!("{}_2", COOKIE_AUTH_USER_PREFIX),
                "value2",
            ))
            .cookie(Cookie::new("session_id", "session_value"))
            .to_http_request();

        // Create an HttpResponseBuilder to capture the response cookies
        let mut response = HttpResponse::Ok();

        // Call the remove_auth_cookies function
        CookieHelper::remove_auth_cookies(&req, &mut response);

        // Get the response cookies to verify which cookies were removed
        let response_cookies: Vec<_> = response
            .finish()
            .headers()
            .get_all(header::SET_COOKIE)
            .map(|header_value| header_value.to_str().unwrap().to_string())
            .collect();

        // Assert that only the "COOKIE_AUTH_USER_PREFIX" prefixed cookies are marked for removal
        assert!(response_cookies.iter().any(|c| c.starts_with(&format!(
            "{}_1=; Path=/; Max-Age=0",
            COOKIE_AUTH_USER_PREFIX
        ))));
        assert!(response_cookies.iter().any(|c| c.starts_with(&format!(
            "{}_2=; Path=/; Max-Age=0",
            COOKIE_AUTH_USER_PREFIX
        ))));
        assert!(!response_cookies
            .iter()
            .any(|c| c.starts_with("session_id=; Max-Age=0")));
    }

    #[test]
    fn test_get_dead_cookies() {
        // Arrange
        let chunker_cookies = vec![
            Cookie::new("test_cookie_1", "chunker_value1"),
            Cookie::new("test_cookie_2", "chunker_value2"),
            Cookie::new("test_cookie_3", "chunker_value3"),
        ];

        let chunker = CookieChunker {
            cookie_name_prefix: "test_cookie",
            cookies: chunker_cookies.clone(),
        };

        // These cookies will be passed to the `get_dead_cookies` method.
        let prior_cookies = vec![
            Cookie::new("test_cookie_1", "passed_value1"), // Matching cookie
            Cookie::new("test_cookie_2", "passed_value2"), // Matching cookie
            Cookie::new("test_cookie_4", "passed_value4"), // Non-matching cookie
            Cookie::new("test_cookie_5", "passed_value5"), // Non-matching cookie
            Cookie::new("other_cookie_1", "passed_value3"), // Non-matching prefix
        ];

        let cookie_name_prefix = "test_cookie";

        // Act
        let dead_cookies = chunker.get_dead_cookies(&prior_cookies, cookie_name_prefix);

        // Assert
        // We expect `test_cookie_1` and `test_cookie_2` to be returned as dead cookies
        assert_eq!(dead_cookies.len(), 2, "Expected two dead cookies");
        assert_eq!(dead_cookies[0].name(), "test_cookie_4");
        assert_eq!(dead_cookies[0].value(), "passed_value4");
        assert_eq!(dead_cookies[1].name(), "test_cookie_5");
        assert_eq!(dead_cookies[1].value(), "passed_value5");
    }

    #[test]
    fn test_cookie_attributes() {
        // Arrange
        let long_string = "This is a test string that will be split into multiple cookies.";
        let cookie_name_prefix = "test_cookie";
        let max_cookie_size = 10;
        let expiry = Expiration::DateTime(OffsetDateTime::now_utc());

        // Act
        let result = CookieChunker::from_string_with_size(
            long_string,
            cookie_name_prefix,
            max_cookie_size,
            expiry,
            CookiePath::All,
        );

        // Assert
        assert!(result.is_ok(), "Expected successful cookie creation");
        let chunker = result.unwrap();

        // Verify that each cookie has the required attributes
        for cookie in chunker.cookies {
            assert_eq!(cookie.http_only(), Some(true), "Cookie should be HTTP-only");
            assert_eq!(
                cookie.same_site(),
                Some(SameSite::Lax),
                "Cookie should have SameSite=Lax"
            );
            assert_eq!(cookie.secure(), Some(true), "Cookie should be Secure");
            assert_eq!(cookie.path().unwrap(), "/", "Cookie should have path '/'");
            assert_eq!(
                cookie.expires().unwrap().datetime().unwrap(),
                expiry.datetime().unwrap(),
                "Cookie should have expiry set to utc now"
            );
        }
    }

    #[macro_export]
    macro_rules! test_from_string_with_size {
        ($name:ident, $long_string:expr, $max_cookie_size:expr, $expected_values:expr) => {
            #[test]
            fn $name() {
                let cookie_name_prefix = "test_cookie";

                let result = CookieChunker::from_string_with_size(
                    $long_string,
                    cookie_name_prefix,
                    $max_cookie_size,
                    Expiration::DateTime(OffsetDateTime::now_utc()),
                    CookiePath::All,
                );

                assert!(result.is_ok(), "Expected successful cookie chunking");

                let cookie_chunker = result.unwrap();

                assert_eq!(cookie_chunker.cookies.len(), $expected_values.len());

                for (i, cookie) in cookie_chunker.cookies.iter().enumerate() {
                    assert_eq!(cookie.name(), format!("{}_{}", cookie_name_prefix, i + 1));
                    assert_eq!(cookie.value(), $expected_values[i]);
                }
            }
        };
    }

    test_from_string_with_size!(
        test_ascii_string,
        "Hello, world! This is a test string.",
        5,
        vec!["Hello", ", wor", "ld! T", "his i", "s a t", "est s", "tring", "."]
    );

    test_from_string_with_size!(
        test_multibyte_string,
        "こんにちは世界",
        8,
        vec!["こん", "にち", "は世", "界"]
    );

    #[test]
    fn test_to_string_success() {
        // Arrange
        let plain_text = "This is part 1.This is part 2.This is part 3.";
        let part1_len = 10;
        let part2_len = 10;
        let encrypted = CookieCrypto::encrypt(plain_text).unwrap();
        let part1 = &encrypted[0..part1_len];
        let part2 = &encrypted[part1_len..part1_len + part2_len];
        let part3 = &encrypted[part1_len + part2_len..];
        let cookies = vec![
            Cookie::new("test_cookie_1", part1),
            Cookie::new("test_cookie_2", part2),
            Cookie::new("test_cookie_3", part3),
        ];

        let cookie_name_prefix = "test_cookie";

        let chunker = CookieChunker {
            cookie_name_prefix,
            cookies: cookies.clone(),
        };

        // Act
        let result = chunker.to_string();

        // Assert
        assert!(result.is_ok(), "Expected successful string concatenation");

        let concatenated_string = result.unwrap();
        assert_eq!(
            concatenated_string, "This is part 1.This is part 2.This is part 3.",
            "Concatenated string should match the expected value"
        );
    }

    #[test]
    fn test_to_string_invalid_part_number() {
        // Arrange
        let cookies = vec![
            Cookie::new("test_cookie_1", "This is part 1."),
            Cookie::new("test_cookie_foo", "Invalid part number"), // Invalid part number
            Cookie::new("test_cookie_3", "This is part 3."),
        ];

        let cookie_name_prefix = "test_cookie";

        let chunker = CookieChunker {
            cookie_name_prefix,
            cookies,
        };

        // Act
        let result = chunker.to_string();

        // Assert
        assert!(matches!(
            result,
            Err(ChunkerError::InvalidPartNumber { cookie_name }) if cookie_name == "test_cookie_foo"
        ));
    }

    #[test]
    fn test_from_cookies_success() {
        // Arrange
        let cookies = [
            Cookie::new("test_cookie_1", "value1"),
            Cookie::new("test_cookie_2", "value2"),
            Cookie::new("other_cookie_1", "value3"), // Should be filtered out
        ];

        let cookie_name_prefix = "test_cookie";

        // Act
        let result = CookieChunker::from_cookies(&cookies, cookie_name_prefix);

        // Assert
        assert!(result.is_ok());
        let chunker = result.unwrap();
        assert_eq!(chunker.cookies.len(), 2); // Only 2 cookies with matching prefix
        assert_eq!(chunker.cookies[0].name(), "test_cookie_1");
        assert_eq!(chunker.cookies[1].name(), "test_cookie_2");
    }

    #[test]
    fn test_from_cookies_no_matches() {
        // Arrange
        let cookies = [
            Cookie::new("other_cookie_1", "value1"),
            Cookie::new("another_cookie_2", "value2"),
        ];

        let cookie_name_prefix = "test_cookie";

        // Act
        let chunker = CookieChunker::from_cookies(&cookies, cookie_name_prefix);

        // Assert
        assert!(
            matches!(chunker, Err(ChunkerError::Empty { prefix }) if prefix == cookie_name_prefix)
        ); // No cookies should match the prefix
    }
}
