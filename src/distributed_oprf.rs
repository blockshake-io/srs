use std::sync::Arc;

use actix_web::http::StatusCode;
use blstrs::{G2Affine, Gt};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use srs_opaque::shamir::{self, EvaluatedElement};
use tokio::task;

use crate::{
    constants::USERNAME_OBFUSCATION, error::ErrorCode, servers::indexer::AppState, util,
    Error, Result,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindEvaluateRequest {
    public_input: String,
    #[serde(with = "srs_opaque::serialization::b64_g2")]
    blinded_element: G2Affine,
}

async fn relay_request(
    host: String,
    request: Arc<BlindEvaluateRequest>,
) -> std::result::Result<EvaluatedElement, u16> {
    let e500 = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
    let resp = reqwest::Client::new()
        .post(format!("{}/api/blind-evaluate", host))
        .header("Content-Type", "application/json")
        .json(request.as_ref())
        .send()
        .await
        .map_err(|_| e500)?;

    if resp.status().is_success() {
        Ok(resp.json().await.map_err(|_| e500)?)
    } else {
        Err(resp.status().as_u16())
    }
}

pub async fn blind_evaluate(
    state: &AppState,
    blinded_element: &G2Affine,
    public_input: &[u8],
) -> Result<Gt> {
    let obfuscated_public_input =
        srs_opaque::oprf::evaluate(public_input, USERNAME_OBFUSCATION, &state.username_oprf_key)?;
    let obfuscated_public_input = util::b64_encode(&obfuscated_public_input[..]);

    // TODO: do we need to put this in an Arc?
    let request = Arc::new(BlindEvaluateRequest {
        blinded_element: *blinded_element,
        public_input: obfuscated_public_input,
    });

    // initiate relayed requests...
    let mut futures = vec![];
    for host in &state.oprf_hosts {
        futures.push(task::spawn(relay_request(
            host[..].to_owned(),
            request.clone(),
        )));
    }
    // ... and wait for their completion
    let responses = join_all(futures).await;

    let mut results = vec![];
    let mut rate_limited_requests = 0;

    for response in responses {
        if let Ok(response) = response {
            match response {
                Ok(r) => results.push(r),
                Err(status) => {
                    if status == StatusCode::TOO_MANY_REQUESTS.as_u16() {
                        rate_limited_requests += 1;
                    }
                }
            }
        }
    }

    // if there weren't enough successful requests to recvoer the secret,
    // but there were enough rate-limited requests, we report rate-limiting
    // as error
    let threshold = state.oprf_threshold as usize;
    if results.len() < threshold && rate_limited_requests >= threshold {
        return Err(Error {
            status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
            message: "rate limit exceeded".to_owned(),
            code: ErrorCode::RateLimitExceededError,
            cause: None,
        });
    }

    Ok(shamir::lagrange_interpolation(
        state.oprf_threshold,
        &results,
    )?)
}
