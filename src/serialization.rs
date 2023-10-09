pub mod b64_payload {
    use crate::{error, ksf::KsfParams, util};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use srs_opaque::payload::Payload;

    pub fn serialize<S: Serializer>(v: &KsfParams, s: S) -> Result<S::Ok, S::Error> {
        let buf = v
            .to_bytes()
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
        Ok(KsfParams::from_bytes(&buf)?)
    }
}

pub mod rfc33339 {
    use chrono::{DateTime, FixedOffset};
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&v.to_rfc3339(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<FixedOffset>, D::Error> {
        let datetime = String::deserialize(d)?;
        let datetime = DateTime::parse_from_rfc3339(&datetime[..])
            .map_err(|_| serde::de::Error::custom("Deserialization error for rfc3339 timestamp"))?;
        Ok(datetime)
    }
}
