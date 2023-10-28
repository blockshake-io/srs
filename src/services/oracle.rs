use std::sync::Arc;

use actix_web::http::StatusCode;
use blstrs::{G2Affine, Gt, Scalar};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use srs_opaque::shamir::{self, EvaluatedElement};
use tokio::task;

use crate::{
    constants::USERNAME_OBFUSCATION, error::ErrorCode, servers::indexer::AppState, util, Error,
    Result,
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

/// We obfuscate the username before we send it to oracle servers such that
/// they cannot track the usernames that access the indexer. The username is
/// obfuscated with a PRF and the result is base64-encoded.
pub fn obfuscate_username(username: &str, oprf_key: &Scalar) -> Result<String> {
    let obfuscated_public_input =
        srs_opaque::oprf::evaluate(username.as_bytes(), USERNAME_OBFUSCATION, oprf_key)?;
    Ok(util::b64_encode(&obfuscated_public_input[..]))
}

pub async fn blind_evaluate(
    state: &AppState,
    blinded_element: &G2Affine,
    public_input: String,
) -> Result<Gt> {
    let request = Arc::new(BlindEvaluateRequest {
        blinded_element: *blinded_element,
        public_input,
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

    let threshold = state.oprf_threshold as usize;
    if results.len() < threshold {
        if rate_limited_requests >= threshold {
            // if there are enough rate-limited requests, we report rate-limiting
            // as error
            return Err(Error {
                status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                code: ErrorCode::RateLimitExceededError,
                message: "rate limit exceeded".to_owned(),
                source: None,
            });
        } else {
            // we couldn't get enough oracle servers to respond, so we abort
            return Err(Error {
                status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                code: ErrorCode::OraclesUnavailableError,
                message: "insufficient number of oracles available".to_owned(),
                source: None,
            });
        }
    }

    Ok(shamir::lagrange_interpolation(
        state.oprf_threshold,
        &results,
    )?)
}
