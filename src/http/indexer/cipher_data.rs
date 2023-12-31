use std::sync::Arc;

use crate::{
    db, error::ErrorCode, models::CipherDataListItem, servers::indexer::AppState,
    session::SrsSession, Error, Result,
};
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

// a file cannot be larger than 100kb;
const MAX_UPLOAD_SIZE: usize = 102400;

pub async fn post_cipher_data(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Query<PostCipherDbRequest>,
    mut payload: Multipart,
) -> Result<CipherDataListItem> {
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

    let item = db::cipher_data::insert_cipher_data(
        &state.db,
        &session.user_id,
        &session.key_version,
        data.application_id,
        &data.format,
        &buffer[..],
    )
    .await?;

    Ok(item)
}

impl Responder for CipherDataListItem {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Created()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetChiperDbRequest {
    pub application_id: Option<i64>,
    pub format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetChiperDbsResponse {
    pub results: Vec<CipherDataListItem>,
}

impl Responder for GetChiperDbsResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn get_cipher_data(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Query<GetChiperDbRequest>,
) -> Result<GetChiperDbsResponse> {
    let session = session.check_authenticated(&mut state.redis.get_connection()?)?;

    let results = db::cipher_data::get_cipher_data_list(
        &state.db,
        &session.user_id,
        data.application_id,
        data.format.as_ref().map(|v| v.as_str()),
    )
    .await?;

    Ok(GetChiperDbsResponse { results })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetChiperDataResponse {
    pub cipher_data: Vec<u8>,
}

impl Responder for GetChiperDataResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::octet_stream())
            .body(self.cipher_data)
    }
}

pub async fn download_cipher_data(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Path<i64>,
) -> Result<GetChiperDataResponse> {
    let session = session.check_authenticated(&mut state.redis.get_connection()?)?;
    let cipher_data = db::cipher_data::get_cipher_data(&state.db, *data).await?;
    if cipher_data.user_id.0 != session.user_id.0 {
        return Err(Error {
            status: StatusCode::FORBIDDEN.as_u16(),
            code: ErrorCode::ForbiddenError,
            message: "access forbidden".to_owned(),
            source: None,
        });
    }

    Ok(GetChiperDataResponse {
        cipher_data: cipher_data.ciphertext,
    })
}
