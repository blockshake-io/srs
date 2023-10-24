use crate::{error::ErrorCode, Error, Result};
use actix_web::http::StatusCode;
use regex::Regex;

pub const MAX_PUBLIC_INPUT_LEN: usize = 100;

pub fn validate_public_input(public_input: &str) -> Result<()> {
    if public_input.is_empty() {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "public_input may not be empty".to_owned(),
            source: None,
        });
    }
    if public_input.len() > MAX_PUBLIC_INPUT_LEN {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "public_input may not exceed 100 characters".to_owned(),
            source: None,
        });
    }
    Ok(())
}

lazy_static! {
    static ref USERNAME_REGEX: Regex =
        Regex::new(r"^[a-zA-Z0-9._+-]{3,32}(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$").unwrap();
}

pub fn validate_username(username: &str) -> Result<()> {
    match USERNAME_REGEX.captures(username) {
        Some(_) => Ok(()),
        None => Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            message: "Could not validate username".to_owned(),
            code: crate::error::ErrorCode::ValidationError,
            source: None,
        }),
    }
}