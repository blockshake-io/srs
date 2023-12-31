use chrono::NaiveDateTime;
use reqwest::StatusCode;
use tokio_pg_mapper::FromTokioPostgresRow;
use tokio_postgres::types::ToSql;

use crate::{
    models::{CipherData, CipherDataListItem, KeyVersion, UserId},
    Error, Result,
};

pub async fn insert_cipher_data(
    db: &deadpool_postgres::Pool,
    user_id: &UserId,
    key_version: &KeyVersion,
    application_id: i64,
    format: &str,
    ciphertext: &[u8],
) -> Result<CipherDataListItem> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/cipher_data_insert.sql");
    let stmt = client.prepare(stmt).await?;
    let result = client
        .query(
            &stmt,
            &[
                &user_id.0,
                &key_version.0,
                &application_id,
                &format,
                &ciphertext,
            ],
        )
        .await?;

    assert!(result.len() == 1);
    let row = result.first().unwrap();
    let id = row.get::<&str, i64>("id");
    let created_at = row.get::<&str, NaiveDateTime>("created_at");

    Ok(CipherDataListItem {
        id,
        application_id,
        format: format.to_owned(),
        key_version: key_version.clone(),
        created_at,
    })
}

pub async fn get_cipher_data_list(
    db: &deadpool_postgres::Pool,
    user_id: &UserId,
    application_id: Option<i64>,
    format: Option<&str>,
) -> Result<Vec<CipherDataListItem>> {
    let client = db.get().await?;

    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&user_id.0];
    let mut stmt = "
        select id, application_id, format, key_version, created_at
        from cipher_data
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

    let mut result: Vec<CipherDataListItem> = vec![];
    for row in query_result {
        result.push(CipherDataListItem::from_row(row)?);
    }

    Ok(result)
}

pub async fn get_cipher_data(db: &deadpool_postgres::Pool, id: i64) -> Result<CipherData> {
    let client = db.get().await?;
    let stmt = include_str!("../../db/queries/cipher_data_select.sql");
    let stmt = client.prepare(stmt).await?;
    let result = client.query(&stmt, &[&id]).await?;

    match result.first() {
        Some(row) => Ok(CipherData::from_row_ref(row)?),
        None => Err(Error {
            status: StatusCode::NOT_FOUND.as_u16(),
            code: crate::error::ErrorCode::NotFoundError,
            message: "could not find record".to_owned(),
            source: None,
        }),
    }
}
