use srs_opaque::messages::RegistrationRecord;
use tokio_postgres::types::Json;

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
