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
