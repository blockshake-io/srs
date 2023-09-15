pub mod b64_g2 {
    use crate::util;

    use blstrs::G2Affine;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use typenum::U96;

    pub fn serialize<S: Serializer>(v: &G2Affine, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v.to_compressed());
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<G2Affine, D::Error> {
        let b64 = String::deserialize(d)?;
        util::b64_decode::<U96>(&b64)
            .ok()
            .and_then(|data| {
                let buf: &[u8; 96] = data[..].try_into().unwrap();
                G2Affine::from_compressed(buf).into()
            })
            .ok_or_else(|| serde::de::Error::custom("Deserialization error for G2"))
    }
}

pub mod b64_gt {
    use crate::util;

    use blstrs::{Compress, Gt};
    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::LenGt;

    pub fn serialize<S: Serializer>(v: &Gt, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = GenericArray::<u8, LenGt>::default();
        v.write_compressed(&mut buf[..])
            .map_err(|_| serde::ser::Error::custom("Serialization error for Gt"))?;
        let b64 = util::b64_encode(&buf);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Gt, D::Error> {
        let buf: GenericArray<u8, LenGt> = util::b64_decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for Gt"))?;
        Gt::read_compressed(&buf[..])
            .map_err(|_| serde::de::Error::custom("Deserialization error for Gt"))
    }
}

pub mod b64_public_key {
    use crate::error;
    use crate::util;

    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::LenKePublicKey;
    use srs_opaque::keypair::PublicKey;

    pub fn serialize<S: Serializer>(v: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v.serialize()[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for public key"))
    }

    pub fn decode(input: &str) -> Result<PublicKey, error::Error> {
        let buf: GenericArray<u8, LenKePublicKey> = util::b64_decode(input)?;
        Ok(PublicKey::deserialize(&buf[..])?)
    }
}

pub mod b64_digest {
    use crate::error;
    use crate::util::{self, b64_decode};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::Digest;

    pub fn serialize<S: Serializer>(v: &Digest, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for digest"))
    }

    pub fn decode(input: &str) -> Result<Digest, error::Error> {
        b64_decode(input)
    }
}

pub mod b64_nonce {
    use crate::error;
    use crate::util::{self, b64_decode};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::Nonce;

    pub fn serialize<S: Serializer>(v: &Nonce, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Nonce, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for nonce"))
    }

    pub fn decode(input: &str) -> Result<Nonce, error::Error> {
        b64_decode(input)
    }
}

pub mod b64_auth_code {
    use crate::error;
    use crate::util::{self, b64_decode};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::AuthCode;

    pub fn serialize<S: Serializer>(v: &AuthCode, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AuthCode, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for auth_code"))
    }

    pub fn decode(input: &str) -> Result<AuthCode, error::Error> {
        b64_decode(input)
    }
}

pub mod b64_envelope {
    use crate::{error, util};

    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::LenEnvelope;
    use srs_opaque::messages::Envelope;

    pub fn serialize<S: Serializer>(v: &Envelope, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v.serialize());
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Envelope, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for envelope"))
    }

    pub fn decode(input: &str) -> Result<Envelope, error::Error> {
        let buf: GenericArray<u8, LenEnvelope> = util::b64_decode(input)?;
        Ok(Envelope::deserialize(&buf[..])?)
    }
}

pub mod b64_payload {
    use crate::{error, util, KsfParams};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::payload::Payload;

    pub fn serialize<S: Serializer>(v: &KsfParams, s: S) -> Result<S::Ok, S::Error> {
        let buf = v
            .serialize()
            .map_err(|_| serde::ser::Error::custom("Serialization error for payload"))?;
        let b64 = util::b64_encode(&buf[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<KsfParams, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for payload"))
    }

    pub fn decode(input: &str) -> Result<KsfParams, error::Error> {
        let buf = util::b64_decode(input)?;
        Ok(KsfParams::deserialize(&buf)?)
    }
}

pub mod b64_masked_response {
    use crate::{error, util};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::ciphersuite::{Bytes, LenMaskedResponse};

    pub fn serialize<S: Serializer>(v: &Bytes<LenMaskedResponse>, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Bytes<LenMaskedResponse>, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for masked_response"))
    }

    pub fn decode(input: &str) -> Result<Bytes<LenMaskedResponse>, error::Error> {
        util::b64_decode(input)
    }
}

pub mod b64_scalar {
    use crate::util;

    use blstrs::Scalar;
    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use typenum::U32;

    pub fn serialize<S: Serializer>(v: &Scalar, s: S) -> Result<S::Ok, S::Error> {
        let b64 = util::b64_encode(&v.to_bytes_be());
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Scalar, D::Error> {
        let buf: GenericArray<u8, U32> = util::b64_decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for scalar"))?;
        let buf: [u8; 32] = buf.try_into().unwrap();
        let scalar = Scalar::from_bytes_be(&buf);
        if bool::from(scalar.is_some()) {
            Ok(scalar.unwrap())
        } else {
            Err(serde::de::Error::custom("Could not parse BLS12-381 scalar"))
        }
    }
}
