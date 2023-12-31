use srs_opaque::messages::RegistrationRecord;
use tokio_postgres::types::Json;

use crate::{
    error::{ErrorCode::MissingRecordError, Source},
    models::{KeyVersion, User, UserId},
    Error, Result,
};

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
    let key_version = KeyVersion(row.get::<&str, i64>("key_version"));
    let registration_record = row.get::<&str, Json<_>>("registration_record");

    Ok(User {
        id,
        key_version,
        registration_record: registration_record.0,
    })
}

pub async fn insert_user(
    db: &deadpool_postgres::Pool,
    username: &str,
    key_version: KeyVersion,
    registration_record: &RegistrationRecord,
) -> Result<()> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/user_insert.sql");
    let stmt = client.prepare(stmt).await?;
    client
        .query(
            &stmt,
            &[&username, &key_version.0, &Json(registration_record)],
        )
        .await
        .map_err(|e| Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::UsernameTakenError,
            message: format!("username '{}' is taken", &username),
            source: Some(Source::DbError(e)),
        })?;

    Ok(())
}
