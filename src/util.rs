use crate::{error::ErrorCode, Error, Result};
use base64::Engine;
use generic_array::{ArrayLength, GenericArray};
use srs_opaque::ciphersuite::Bytes;

pub fn b64_decode<Len>(input: &str) -> Result<GenericArray<u8, Len>>
where
    Len: ArrayLength<u8>,
{
    let mut buf = Bytes::<Len>::default();
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)?;
    if data.len() != Len::to_usize() {
        return Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::DeserializationError,
            message: "Incorrect length of base64-encoded input".to_owned(),
            cause: None,
        });
    }
    buf.copy_from_slice(&data[..]);
    Ok(buf)
}

pub fn b64_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}
