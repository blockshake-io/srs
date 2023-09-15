use std::future::{Ready, ready};

use actix_web::{FromRequest, dev::Payload, HttpRequest};
use redis::Commands;
use regex::Regex;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::{Serialize, Deserialize};

use crate::{Error, UserId, redis::{ToRedisKey, NS_SESSION}};

lazy_static! {
    static ref SESSION_KEY_REGEX: Regex =
        Regex::new(r"^Bearer (?P<session_key>[a-zA-Z0-9]{64})$").unwrap();
}

const STR_AUTHORIZATION: &str = "Authorization";

#[derive(Debug)]
pub struct SessionKey {
    key: String,
}

impl SessionKey {
    /// Extracts a session key from the value of an Authorization header
    /// in the format "Bearer XYZ"
    pub fn from_bearer_token(input: &str) -> crate::Result<SessionKey> {
        if let Some(caps) = SESSION_KEY_REGEX.captures(input) {
            let session_key = caps["session_key"].to_owned();
            Ok(SessionKey { key: session_key })
        } else {
            Err(Error {
                status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                code: crate::error::ErrorCode::ValidationError,
                message: "Could not validate session key".to_owned(),
                cause: None,
            })
        }
    }

    /// This is copied from actix-session code
    ///
    /// Session key generation routine that follows [OWASP recommendations].
    ///
    /// [OWASP recommendations]: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy
    pub fn random() -> SessionKey {
        let value = std::iter::repeat(())
            .map(|_| OsRng.sample(Alphanumeric))
            .take(64)
            .collect::<Vec<_>>();

        // These unwraps will never panic because pre-conditions are always verified
        // (i.e. length and character set)
        SessionKey {
            key: String::from_utf8(value).unwrap()
        }
    }

    pub fn to_str(&self) -> String {
        self.key.clone()
    }

    pub fn as_str(&self) -> &str {
        &self.key
    }

    pub fn to_redis_key(&self) -> String {
        self.key.to_redis_key(NS_SESSION)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    user_id: UserId,
}

impl SessionData {
    fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn from_json(input: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str::<SessionData>(input)?)
    }
}

pub struct SrsSession {
    session_key: Option<SessionKey>,
}

// TODO: should we add an expiration date to this token?
// see https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
impl SrsSession {
    pub fn zero() -> SrsSession {
        SrsSession { session_key: None }
    }

    pub fn create(user_id: &UserId, conn: &mut redis::Connection) -> crate::Result<SrsSession> {
        let session_key = SessionKey::random();
        let session_data = SessionData { user_id: *user_id };
        // TODO: expire the session after some time
        conn.set(session_key.to_redis_key(), session_data.to_json()?)?;
        Ok(SrsSession { session_key: Some(session_key) })
    }

    pub fn data(&self, conn: &mut redis::Connection) -> Option<SessionData> {
        if self.session_key.is_none() {
            return None;
        }
        let key = self.session_key.as_ref().unwrap();
        let result: Result<String, _> = conn.get(key.to_redis_key());
        if result.is_err() {
            return None;
        }
        SessionData::from_json(&result.unwrap()).ok()
    }

    pub fn is_authenticated(&self, conn: &mut redis::Connection) -> bool {
        self.data(conn).is_some()
    }

    pub fn key(&self) -> Option<&SessionKey> {
        self.session_key.as_ref()
    }
}

impl FromRequest for SrsSession {
    type Error = Error;

    // Rust does not yet support the `async` syntax in traits.
    // From request expects a `Future` as return type to allow for extractors
    // that need to perform asynchronous operations (e.g. a HTTP call)
    // We do not have a `Future`, because we don't perform any I/O,
    // so we wrap `SrsSession` into `Ready` to convert it into a `Future` that
    // resolves to the wrapped value the first time it's polled by the executor.
    type Future = Ready<Result<SrsSession, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let header = req.headers().get(STR_AUTHORIZATION);
        if header.is_none() {
            return ready(Ok(SrsSession::zero()))
        }
        // it's safe to unwrap here because we made sure with the regex that
        // the session key is a valid strind
        let header = header.unwrap().to_str().unwrap();
        let session_key = SessionKey::from_bearer_token(header);

        if session_key.is_ok() {
            let session = SrsSession { session_key: Some(session_key.unwrap()) };
            ready(Ok(session))
        } else {
            ready(Ok(SrsSession::zero()))
        }
    }
}