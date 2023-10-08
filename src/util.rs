use crate::{error::ErrorCode, Error, Result};
use base64::Engine;
use generic_array::{ArrayLength, GenericArray};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha512_256};
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

pub fn crypto_rng_from_seed(seed: &[u8]) -> ChaCha20Rng {
    let hashed_seed = Sha512_256::digest(seed);
    ChaCha20Rng::from_seed(hashed_seed.into())
}
