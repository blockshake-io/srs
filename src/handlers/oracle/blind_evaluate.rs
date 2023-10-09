use std::sync::Arc;

use crate::{
    error::ErrorCode, rate_limiter::check_rate_limit, servers::oracle::AppState, Error, Result,
};
use actix_web::{
    body::BoxBody,
    http::{header::ContentType, StatusCode},
    web, HttpRequest, HttpResponse, Responder,
};
use blstrs::{G2Affine, Gt};
use serde::{Deserialize, Serialize};
use srs_opaque::{oprf::blind_evaluate, serialization};

pub const MAX_PUBLIC_INPUT_LEN: usize = 100;

pub async fn blind_evaluate_endpoint(
    state: web::Data<Arc<AppState>>,
    data: web::Json<BlindEvaluateRequest>,
) -> Result<EvaluatedElement> {
    // validate request & rate-limit
    validate_public_input(&data.public_input)?;
    check_rate_limit(&mut state.redis.get_connection()?, &data.public_input)?;

    let evaluated_element = blind_evaluate(
        &data.blinded_element,
        data.public_input.as_bytes(),
        &state.secret_key_share,
    );

    Ok(EvaluatedElement {
        evaluated_element,
        server_id: state.secret_key_index,
    })
}

fn validate_public_input(public_input: &str) -> Result<()> {
    if public_input.is_empty() {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "public_input may not be empty".to_owned(),
            cause: None,
        });
    }
    if public_input.len() > MAX_PUBLIC_INPUT_LEN {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: ErrorCode::ValidationError,
            message: "public_input may not exceed 100 characters".to_owned(),
            cause: None,
        });
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct BlindEvaluateRequest {
    pub public_input: String,
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatedElement {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    pub server_id: u64,
}

impl Responder for EvaluatedElement {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}
