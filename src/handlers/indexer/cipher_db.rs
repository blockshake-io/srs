use std::sync::Arc;

use crate::{error::ErrorCode, servers::indexer::AppState, session::SrsSession, Error, Result};
use actix_multipart::Multipart;
use actix_web::{
    body::BoxBody,
    http::{header::ContentType, StatusCode},
    web, HttpRequest, HttpResponse, Responder,
};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PostCipherDbRequest {
    pub application_id: i64,
    pub format: String,
}

#[derive(Serialize, Deserialize)]
pub struct SuccessResponse {
    message: String,
}

// a file cannot be larger than 100kb;
const MAX_UPLOAD_SIZE: usize = 102400;

impl Responder for SuccessResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn post_cipher_db(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Query<PostCipherDbRequest>,
    mut payload: Multipart,
) -> Result<SuccessResponse> {
    let session = session.check_authenticated(&mut state.redis.get_connection()?)?;

    // read the first field
    let mut field = match payload.try_next().await {
        Ok(Some(f)) => Ok(f),
        _ => Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "expected file".to_string(),
            source: None,
        }),
    }?;

    // ensure the field is properly named
    if field.name() != "file" {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "expected field name 'file'".to_string(),
            source: None,
        });
    }

    // buffer the uploaded file in memory
    let mut buffer = Vec::<u8>::with_capacity(1024);
    while let Ok(Some(chunk)) = field.try_next().await {
        buffer.extend_from_slice(&chunk);
        if buffer.len() > MAX_UPLOAD_SIZE {
            return Err(Error {
                status: StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                code: ErrorCode::PayloadTooLargeError,
                message: format!("the maximum file size is {} bytes", MAX_UPLOAD_SIZE),
                source: None,
            });
        }
    }

    crate::db::insert_cipher_db(
        &state.db,
        &session.user_id,
        data.application_id,
        &data.format,
        &buffer[..],
    )
    .await?;

    Ok(SuccessResponse {
        message: "success".to_owned(),
    })
}