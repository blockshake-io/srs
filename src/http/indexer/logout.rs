use std::sync::Arc;

use crate::{servers::indexer::AppState, session::SrsSession, Result};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    success: bool,
}

impl Responder for LogoutResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn logout(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
) -> Result<LogoutResponse> {
    let redis = &mut state.redis.get_connection()?;
    let session = session.check_authenticated(redis)?;
    SrsSession::delete(&session, redis)?;
    Ok(LogoutResponse { success: true })
}
