use crate::{error::ErrorCode, Error, Result};
use actix_web::http::StatusCode;

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
