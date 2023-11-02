use chrono::NaiveDateTime;
use postgres_protocol::types;
use serde::{Deserialize, Serialize};
use srs_opaque::messages::RegistrationRecord;
use tokio_pg_mapper_derive::PostgresMapper;
use tokio_postgres::types::FromSql;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UserId(pub i64);

impl From<i64> for UserId {
    fn from(value: i64) -> Self {
        UserId(value)
    }
}

impl<'a> FromSql<'a> for UserId {
    fn from_sql(
        _: &tokio_postgres::types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(UserId(types::int8_from_sql(raw)?))
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        ty.name() == "int8"
    }
}

pub struct User {
    pub id: UserId,
    pub key_version: KeyVersion,
    pub registration_record: RegistrationRecord,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct KeyVersion(pub i64);

impl Default for KeyVersion {
    fn default() -> Self {
        KeyVersion(0)
    }
}

impl From<i64> for KeyVersion {
    fn from(value: i64) -> Self {
        KeyVersion(value)
    }
}

impl<'a> FromSql<'a> for KeyVersion {
    fn from_sql(
        _: &tokio_postgres::types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(KeyVersion(types::int8_from_sql(raw)?))
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        ty.name() == "int8"
    }
}

#[derive(Debug, Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user")]
pub struct CipherDbListItem {
    pub id: i64,
    pub application_id: i64,
    pub format: String,
    pub key_version: KeyVersion,
    #[serde(with = "crate::serialization::iso8601")]
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user")]
pub struct CipherDb {
    pub id: i64,
    pub user_id: UserId,
    pub key_version: KeyVersion,
    pub application_id: i64,
    pub format: String,
    #[serde(with = "crate::serialization::iso8601")]
    pub created_at: NaiveDateTime,
    pub ciphertext: Vec<u8>,
}
