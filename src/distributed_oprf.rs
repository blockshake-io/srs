use std::sync::Arc;

use blstrs::{G2Affine, Gt};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use srs_opaque::shamir::{self, EvaluatedElement};
use tokio::task;

use crate::{util, AppState, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindEvaluateRequest {
    public_input: String,
    #[serde(with = "srs_opaque::serialization::b64_g2")]
    blinded_element: G2Affine,
}

async fn relay_request(
    host: String,
    request: Arc<BlindEvaluateRequest>,
) -> Option<EvaluatedElement> {
    let resp = reqwest::Client::new()
        .post(format!("{}/api/blind-evaluate", host))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(request.as_ref()).ok()?)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    serde_json::from_str(&resp[..]).ok()
}

pub async fn blind_evaluate(
    state: &AppState,
    blinded_element: &G2Affine,
    public_input: &[u8],
) -> Result<Gt> {
    // TODO: do we need to put this in an Arc?
    let request = Arc::new(BlindEvaluateRequest {
        blinded_element: *blinded_element,
        public_input: util::b64_encode(public_input),
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
    for response in responses {
        if response.is_err() {
            continue;
        }
        match response.unwrap() {
            Some(r) => results.push(r),
            None => continue,
        }
    }

    let aggregated_element = shamir::lagrange_interpolation(state.oprf_threshold, &results)?;

    Ok(aggregated_element)
}
