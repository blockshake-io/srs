pub mod iso8601 {
    use chrono::NaiveDateTime;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    const ISO8601_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

    pub fn serialize<S: Serializer>(v: &NaiveDateTime, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&v.format(ISO8601_FORMAT).to_string(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NaiveDateTime, D::Error> {
        let datetime = String::deserialize(d)?;
        let datetime = NaiveDateTime::parse_from_str(&datetime, ISO8601_FORMAT)
            .map_err(|_| serde::de::Error::custom("Deserialization error for rfc3339 timestamp"))?;
        Ok(datetime)
    }
}
