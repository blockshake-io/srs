use std::sync::Arc;

use crate::{
    distributed_oprf, rate_limiter::check_rate_limit, servers::indexer::AppState,
    validators::validate_public_input, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use blstrs::{G2Affine, Gt};
use serde::{Deserialize, Serialize};
use srs_opaque::serialization;

pub async fn blind_evaluate_endpoint(
    state: web::Data<Arc<AppState>>,
    data: web::Json<BlindEvaluateRequest>,
) -> Result<EvaluatedElement> {
    validate_public_input(&data.public_input)?;
    check_rate_limit(&mut state.redis.get_connection()?, &data.public_input)?;

    let evaluated_element = distributed_oprf::blind_evaluate(
        state.get_ref().as_ref(),
        &data.blinded_element,
        data.public_input.as_bytes(),
    )
    .await?;

    Ok(EvaluatedElement { evaluated_element })
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
}

impl Responder for EvaluatedElement {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}
