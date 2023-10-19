use chrono::NaiveDateTime;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use srs_opaque::messages::RegistrationRecord;
use tokio_pg_mapper::FromTokioPostgresRow;
use tokio_pg_mapper_derive::PostgresMapper;
use tokio_postgres::types::{Json, ToSql};

use crate::{
    error::{ErrorCode::MissingRecordError, Source},
    ksf::KsfParams,
    Error, Result, UserId,
};

pub struct User {
    pub id: UserId,
    pub registration_record: RegistrationRecord<KsfParams>,
}

pub async fn select_user_by_username(db: &deadpool_postgres::Pool, username: &str) -> Result<User> {
    let client = db.get().await?;
    let query = include_str!("../../db/queries/registration_record_select.sql");
    let result = client
        .query(&client.prepare(query).await?, &[&username])
        .await?;

    if result.len() != 1 {
        return Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: MissingRecordError,
            message: "Could not find record".to_owned(),
            source: None,
        });
    }

    let row = result.first().unwrap();
    let id = UserId(row.get::<&str, i64>("id"));
    let registration_record = row.get::<&str, Json<_>>("registration_record");

    Ok(User {
        id,
        registration_record: registration_record.0,
    })
}

pub async fn insert_user(
    db: &deadpool_postgres::Pool,
    username: &str,
    registration_record: &RegistrationRecord<KsfParams>,
) -> Result<()> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/user_insert.sql");
    let stmt = client.prepare(stmt).await?;
    client
        .query(&stmt, &[&username, &Json(registration_record)])
        .await
        .map_err(|e| Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::UsernameTakenError,
            message: format!("username '{}' is taken", &username),
            source: Some(Source::DbError(e)),
        })?;

    Ok(())
}

pub async fn insert_cipher_db(
    db: &deadpool_postgres::Pool,
    user_id: &UserId,
    application_id: i64,
    format: &str,
    ciphertext: &[u8],
) -> Result<i64> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/cipher_db_insert.sql");
    let stmt = client.prepare(stmt).await?;
    let result = client
        .query(&stmt, &[&user_id.0, &application_id, &format, &ciphertext])
        .await?;

    assert!(result.len() == 1);
    let row = result.first().unwrap();
    let id = row.get::<&str, i64>("id");

    Ok(id)
}

#[derive(Debug, Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user")]
pub struct CipherDbListItem {
    pub id: i64,
    pub application_id: i64,
    pub format: String,
    #[serde(with = "crate::serialization::iso8601")]
    pub created_at: NaiveDateTime,
}

pub async fn get_cipher_dbs(
    db: &deadpool_postgres::Pool,
    user_id: &UserId,
    application_id: Option<i64>,
    format: Option<&str>,
) -> Result<Vec<CipherDbListItem>> {
    let client = db.get().await?;

    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&user_id.0];
    let mut stmt = "
        select id, application_id, format, created_at
        from cipher_dbs
        where user_id = $1
    "
    .to_owned();

    if let Some(val) = application_id.as_ref() {
        params.push(val);
        stmt += &format!(" and application_id = ${} ", params.len());
    }
    if let Some(val) = format.as_ref() {
        params.push(val);
        stmt += &format!(" and format = ${} ", params.len());
    }
    stmt += " order by created_at desc;";

    let stmt = client.prepare(&stmt).await?;
    let query_result = client.query(&stmt, &params[..]).await?;

    let mut result: Vec<CipherDbListItem> = vec![];
    for row in query_result {
        result.push(CipherDbListItem::from_row(row)?);
    }

    Ok(result)
}

#[derive(Debug, Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user")]
pub struct CipherDb {
    pub id: i64,
    pub user_id: i64,
    pub application_id: i64,
    pub format: String,
    #[serde(with = "crate::serialization::iso8601")]
    pub created_at: NaiveDateTime,
    pub ciphertext: Vec<u8>,
}

pub async fn get_cipher_db(db: &deadpool_postgres::Pool, id: i64) -> Result<CipherDb> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/cipher_db_select.sql");
    let stmt = client.prepare(stmt).await?;
    let result = client.query(&stmt, &[&id]).await?;

    match result.first() {
        Some(row) => Ok(CipherDb::from_row_ref(row)?),
        None => Err(Error {
            status: StatusCode::NOT_FOUND.as_u16(),
            code: crate::error::ErrorCode::NotFoundError,
            message: "could not find record".to_owned(),
            source: None,
        }),
    }
}
