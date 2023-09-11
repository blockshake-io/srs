use crate::{error::ErrorCode, Error, Result};
use actix_session::storage::SessionKey;
use base64::Engine;
use generic_array::{ArrayLength, GenericArray};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
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

/// This is copied from actix-session code
///
/// Session key generation routine that follows [OWASP recommendations].
///
/// [OWASP recommendations]: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy
pub fn generate_session_key() -> SessionKey {
    let value = std::iter::repeat(())
        .map(|_| OsRng.sample(Alphanumeric))
        .take(64)
        .collect::<Vec<_>>();

    // These unwraps will never panic because pre-conditions are always verified
    // (i.e. length and character set)
    String::from_utf8(value).unwrap().try_into().unwrap()
}