use std::sync::Arc;

use crate::{
    servers::oracle::AppState, services::rate_limiter::check_rate_limit,
    validators::validate_public_input, Error, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use blstrs::{G2Affine, Gt};
use serde::{Deserialize, Serialize};
use srs_opaque::{oprf, serialization};

pub const MAX_PUBLIC_INPUT_LEN: usize = 100;

pub async fn blind_evaluate(
    state: web::Data<Arc<AppState>>,
    data: web::Json<BlindEvaluateRequest>,
) -> Result<EvaluatedElement> {
    validate_public_input(&data.public_input)?;
    check_rate_limit(&mut state.redis.get_connection()?, &data.public_input)?;

    let key_version = data.key_version.unwrap_or(state.default_key_version);
    let secret = match state.secret_by_version(key_version) {
        Some(s) => s,
        None => {
            return Err(Error {
                status: actix_web::http::StatusCode::NOT_FOUND.as_u16(),
                code: crate::error::ErrorCode::UnknownKeyVersionError,
                message: format!("key {} not available", key_version),
                source: None,
            });
        }
    };

    let evaluated_element = oprf::blind_evaluate(
        &data.blinded_element,
        data.public_input.as_bytes(),
        &secret.share,
    );

    Ok(EvaluatedElement {
        evaluated_element,
        server_id: secret.index,
        key_version: secret.version,
    })
}

#[derive(Serialize, Deserialize)]
pub struct BlindEvaluateRequest {
    pub public_input: String,
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
    pub key_version: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatedElement {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    pub server_id: u64,
    pub key_version: u64,
}

impl Responder for EvaluatedElement {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}
