use core::fmt::Display;

use actix_web::{body::BoxBody, http::header, http::StatusCode, HttpResponse};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Cause {
    InputParsing,
    Custom(&'static str),
    OpaqueError(srs_opaque::error::Error),
    IoError(std::io::Error),
    SerdeJsonError(serde_json::Error),
    DbError(tokio_postgres::Error),
    DeadpoolPgError(deadpool_postgres::CreatePoolError),
    DeadpoolError,
    Base64Error(base64::DecodeError),
    StdError(Box<dyn std::error::Error>),
    ReqwestError(reqwest::Error),
    Argon2Error(argon2::Error),
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub status: u16,
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip)]
    pub cause: Option<Cause>,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", json)?;
        if self.cause.is_none() {
            return Ok(());
        }
        write!(f, "\n")?;
        match self.cause.as_ref().unwrap() {
            Cause::InputParsing => write!(f, "error parsing input"),
            Cause::IoError(ref err) => Display::fmt(&err, f),
            Cause::SerdeJsonError(ref err) => Display::fmt(&err, f),
            Cause::DbError(ref err) => Display::fmt(&err, f),
            Cause::DeadpoolPgError(ref err) => Display::fmt(&err, f),
            Cause::OpaqueError(ref err) => Display::fmt(&err, f),
            Cause::Base64Error(ref err) => Display::fmt(&err, f),
            Cause::StdError(ref err) => Display::fmt(&err, f),
            Cause::ReqwestError(ref err) => Display::fmt(&err, f),
            Cause::Argon2Error(ref err) => Display::fmt(&err, f),
            Cause::RedisError(ref err) => Display::fmt(&err, f),
            Cause::Custom(err) => write!(f, "Custom: {}", err),
            Cause::DeadpoolError => write!(f, "database error"),
        }
    }
}

impl From<srs_opaque::error::Error> for Error {
    fn from(err: srs_opaque::error::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::OpaqueError(err)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::IoError(err)),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::SerdeJsonError(err)),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(err: tokio_postgres::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::DbError(err)),
        }
    }
}

impl From<deadpool_postgres::CreatePoolError> for Error {
    fn from(err: deadpool_postgres::CreatePoolError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::DeadpoolPgError(err)),
        }
    }
}

impl<E> From<deadpool::managed::PoolError<E>> for Error {
    fn from(_: deadpool::managed::PoolError<E>) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::DeadpoolError),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::Base64Error(err)),
        }
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::StdError(err)),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::ReqwestError(err)),
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::Argon2Error(err)),
        }
    }
}

impl From<redis::RedisError> for Error {
    fn from(err: redis::RedisError) -> Error {
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "".to_owned(),
            cause: Some(Cause::RedisError(err)),
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
