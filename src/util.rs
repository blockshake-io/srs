use crate::{error::ErrorCode, Error, Result};
use actix_session::storage::SessionKey;
use base64::Engine;
use blstrs::{Compress, Gt, Scalar};
use generic_array::{ArrayLength, GenericArray};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use srs_opaque::{
    ciphersuite::{Bytes, LenGt, LenKePublicKey},
    keypair::PublicKey,
};
use typenum::U32;

pub fn b64_encode_gt(x: &Gt) -> Result<String> {
    let mut buf = Bytes::<LenGt>::default();
    x.write_compressed(&mut buf[..])?;
    Ok(b64_encode(&buf))
}

pub fn b64_decode_gt(x: &str) -> Result<Gt> {
    let buf: GenericArray<u8, LenGt> = b64_decode(x)?;
    Ok(Gt::read_compressed(&buf[..])?)
}

pub fn b64_encode_public_key(pk: &PublicKey) -> String {
    b64_encode(&pk.serialize()[..])
}

pub fn b64_decode_public_key(pk: &str) -> Result<PublicKey> {
    let buf: GenericArray<u8, LenKePublicKey> = b64_decode(pk)?;
    Ok(PublicKey::deserialize(&buf[..])?)
}

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
            message: "incorrect length of base64-encoded input".to_owned(),
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

pub fn b64_encode_blstrs_scalar(s: &blstrs::Scalar) -> String {
    b64_encode(&s.to_bytes_be())
}

pub fn b64_decode_blstrs_scalar(s: &str) -> Result<blstrs::Scalar> {
    let buf: GenericArray<u8, U32> = b64_decode(s)?;
    let buf: [u8; 32] = buf.try_into().unwrap();
    let scalar = Scalar::from_bytes_be(&buf);
    if bool::from(scalar.is_some()) {
        Ok(scalar.unwrap())
    } else {
        Err(Error {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::DeserializationError,
            message: "Could not parse BLS12-381 scalar".to_owned(),
            cause: None,
        })
    }
}
