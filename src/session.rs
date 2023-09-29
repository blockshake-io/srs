use std::future::{ready, Ready};

use actix_web::{dev::Payload, FromRequest, HttpRequest};
use chrono::Duration;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use redis::{Commands, FromRedisValue, ToRedisArgs};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    redis::{ToRedisKey, NS_SESSION},
    Error, UserId,
};

lazy_static! {
    static ref SESSION_KEY_REGEX: Regex =
        Regex::new(r"^Bearer (?P<session_key>[a-zA-Z0-9]{64})$").unwrap();
}

const HEADER_AUTHORIZATION: &str = "Authorization";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey(String);

impl SessionKey {
    /// Extracts a session key from the value of an Authorization header
    /// in the format "Bearer XYZ"
    pub fn from_bearer_token(input: &str) -> crate::Result<SessionKey> {
        if let Some(caps) = SESSION_KEY_REGEX.captures(input) {
            let session_key = caps["session_key"].to_owned();
            Ok(SessionKey(session_key))
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
        SessionKey(String::from_utf8(value).unwrap())
    }

    pub fn to_str(&self) -> String {
        self.0.clone()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_redis_key(&self) -> String {
        self.0.to_redis_key(NS_SESSION)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub key: SessionKey,
    pub user_id: UserId,
}

impl FromRedisValue for SessionData {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let v: String = String::from_redis_value(v)?;
        serde_json::from_str(&v[..]).map_err(|e| e.into())
    }
}

impl ToRedisArgs for SessionData {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + redis::RedisWrite,
    {
        let json = serde_json::to_string(&self).expect("session_data can be json-serialized");
        out.write_arg(json.as_bytes())
    }
}

pub struct SrsSession {
    session_key: Option<SessionKey>,
}

impl SrsSession {
    pub fn zero() -> SrsSession {
        SrsSession { session_key: None }
    }

    pub fn create(
        conn: &mut redis::Connection,
        user_id: &UserId,
        ttl: &Duration,
    ) -> crate::Result<SessionData> {
        let session_key = SessionKey::random();
        let session_data = SessionData {
            key: session_key,
            user_id: *user_id,
        };
        conn.set_ex(
            session_data.key.to_redis_key(),
            &session_data,
            ttl.num_seconds() as usize,
        )?;
        Ok(session_data)
    }

    pub fn delete(session: &SessionData, conn: &mut redis::Connection) -> crate::Result<()> {
        conn.del(session.key.to_redis_key())?;
        Ok(())
    }

    pub fn check_authenticated(&self, conn: &mut redis::Connection) -> crate::Result<SessionData> {
        let session_key = self.session_key.as_ref().ok_or_else(|| err401())?;
        conn.get(session_key.to_redis_key()).map_err(|_| err401())
    }

    pub fn check_unauthenticated(&self, conn: &mut redis::Connection) -> crate::Result<()> {
        match self.check_authenticated(conn) {
            Ok(_) => Err(err401()),
            Err(_) => Ok(()),
        }
    }
}

fn err401() -> Error {
    Error {
        status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
        code: crate::error::ErrorCode::AuthenticationError,
        message: "User not authenticated".to_owned(),
        cause: None,
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
        let header = req.headers().get(HEADER_AUTHORIZATION);
        if header.is_none() {
            return ready(Ok(SrsSession::zero()));
        }
        // it's safe to unwrap here because we made sure with the regex that
        // the session key is a valid strind
        let header = header.unwrap().to_str().unwrap();
        let session_key = SessionKey::from_bearer_token(header);

        if session_key.is_ok() {
            let session = SrsSession {
                session_key: Some(session_key.unwrap()),
            };
            ready(Ok(session))
        } else {
            ready(Ok(SrsSession::zero()))
        }
    }
}
