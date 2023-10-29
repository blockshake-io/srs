use base64::Engine;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha512_256};

pub fn b64_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn crypto_rng_from_seed(seed: &[u8]) -> ChaCha20Rng {
    let hashed_seed = Sha512_256::digest(seed);
    ChaCha20Rng::from_seed(hashed_seed.into())
}
