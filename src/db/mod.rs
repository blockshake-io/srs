use srs_opaque::messages::RegistrationRecord;

use crate::{error::ErrorCode::MissingRecordError, Error, KsfParams, Result, serialization, UserId};

pub async fn select_record(
    db: &deadpool_postgres::Pool,
    username: &str,
) -> Result<(UserId, RegistrationRecord<KsfParams>)> {
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
            cause: None,
        });
    }

    let row = result.first().unwrap();

    let user_id = UserId(row.get::<&str, i64>("id") as u64);
    let record = RegistrationRecord {
        envelope: serialization::b64_envelope::decode(row.get("envelope"))?,
        masking_key: serialization::b64_digest::decode(row.get("masking_key"))?,
        client_public_key: serialization::b64_public_key::decode(row.get("client_public_key"))?,
        payload: serialization::b64_payload::decode(row.get("payload"))?,
    };

    Ok((user_id, record))
}
