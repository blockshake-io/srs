use std::fmt::Debug;

use actix_web::{body::BoxBody, http::header, http::StatusCode, HttpResponse};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Source {
    #[error("OPAQUE error: {0}")]
    OpaqueError(srs_opaque::error::Error),
    #[error("I/O Error: {0}")]
    IoError(std::io::Error),
    #[error("Serde Error: {0}")]
    SerdeJsonError(serde_json::Error),
    #[error("Database Error: {0}")]
    DbError(tokio_postgres::Error),
    #[error("Database Error: {0}")]
    PgMapperError(tokio_pg_mapper::Error),
    #[error("Deadpool Error: {0}")]
    DeadpoolPgError(deadpool_postgres::CreatePoolError),
    #[error("Deadpool Error")]
    DeadpoolError,
    #[error("Base64 Error: {0}")]
    Base64Error(base64::DecodeError),
    #[error("Standard Error: {0}")]
    StdError(Box<dyn std::error::Error>),
    #[error("Reqwest Error: {0}")]
    ReqwestError(reqwest::Error),
    #[error("Argon2 Error: {0}")]
    Argon2Error(argon2::Error),
    #[error("Redis Error: {0}")]
    RedisError(redis::RedisError),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ErrorCode {
    MissingRecordError,
    ValidationError,
    DeserializationError,
    InternalError,
    UsernameTakenError,
    AuthenticationError,
    SessionKeyNotFoundError,
    RateLimitExceededError,
    PayloadTooLargeError,
    NotFoundError,
    ForbiddenError,
    OraclesUnavailableError,
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub struct Error {
    pub status: u16,
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip)]
    pub source: Option<Source>,
}

impl Error {
    pub fn internal(message: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: message.to_owned(),
            source: None,
        }
    }
}

impl Default for Error {
    fn default() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", json)?;
        match self.source.as_ref() {
            Some(source) => write!(f, "\n{}", source),
            None => Ok(()),
        }
    }
}

impl From<srs_opaque::error::Error> for Error {
    fn from(err: srs_opaque::error::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::OpaqueError(err)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::IoError(err)),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::SerdeJsonError(err)),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(err: tokio_postgres::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::DbError(err)),
        }
    }
}

impl From<tokio_pg_mapper::Error> for Error {
    fn from(err: tokio_pg_mapper::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::PgMapperError(err)),
        }
    }
}

impl From<deadpool_postgres::CreatePoolError> for Error {
    fn from(err: deadpool_postgres::CreatePoolError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::DeadpoolPgError(err)),
        }
    }
}

impl<E> From<deadpool::managed::PoolError<E>> for Error {
    fn from(_: deadpool::managed::PoolError<E>) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::DeadpoolError),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::Base64Error(err)),
        }
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::StdError(err)),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::ReqwestError(err)),
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::Argon2Error(err)),
        }
    }
}

impl From<redis::RedisError> for Error {
    fn from(err: redis::RedisError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            source: Some(Source::RedisError(err)),
        }
    }
}

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let body = serde_json::to_string(&self);
        if body.is_err() {
            HttpResponse::InternalServerError().finish()
        } else {
            let mut res = HttpResponse::new(self.status_code());
            let mime = HeaderValue::from_static("application/json");
            res.headers_mut().insert(header::CONTENT_TYPE, mime);
            res.set_body(BoxBody::new(body.unwrap()))
        }
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        StatusCode::from_u16(self.status).unwrap()
    }
}
