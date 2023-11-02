use std::sync::Arc;

use crate::{
    models::KeyVersion, servers::indexer::AppState, services::oracle,
    services::rate_limiter::check_rate_limit, validators::validate_public_input, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use blstrs::{G2Affine, Gt};
use serde::{Deserialize, Serialize};
use srs_opaque::serialization;

pub async fn blind_evaluate(
    state: web::Data<Arc<AppState>>,
    data: web::Json<BlindEvaluateRequest>,
) -> Result<EvaluatedElement> {
    validate_public_input(&data.public_input)?;
    check_rate_limit(&mut state.redis.get_connection()?, &data.public_input)?;

    let key_version = data.key_version.unwrap_or(state.default_version);
    let evaluated_element = oracle::blind_evaluate(
        state.get_ref().as_ref(),
        &data.blinded_element,
        data.public_input.clone(),
        key_version,
    )
    .await?;

    Ok(EvaluatedElement {
        evaluated_element,
        key_version,
    })
}

#[derive(Serialize, Deserialize)]
pub struct BlindEvaluateRequest {
    pub public_input: String,
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
    pub key_version: Option<KeyVersion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatedElement {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    pub key_version: KeyVersion
}

impl Responder for EvaluatedElement {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}
