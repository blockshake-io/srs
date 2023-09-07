use blstrs::{G2Affine, Gt};
use regex::Regex;
use std::sync::Arc;

use crate::{error::Cause, serialization, util, AppState, Error, KsfParams, Result};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use srs_opaque::{
    ciphersuite::Digest,
    keypair::PublicKey,
    messages::{Envelope, RegistrationRequest, RegistrationResponse},
    opaque::ServerRegistrationFlow,
    payload::Payload,
};

lazy_static! {
    static ref USERNAME_REGEX: Regex =
        Regex::new(r"^[a-zA-Z0-9._+-]{3,32}(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$").unwrap();
}

#[derive(Deserialize)]
pub struct RegisterStep1Request {
    pub username: String,
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
}

impl TryInto<RegistrationRequest> for RegisterStep1Request {
    type Error = Error;

    fn try_into(self) -> Result<RegistrationRequest> {
        Ok(RegistrationRequest {
            blinded_element: self.blinded_element,
            client_identity: self.username,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStep1Response {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    #[serde(with = "serialization::b64_public_key")]
    pub server_public_key: PublicKey,
    pub session_id: String,
}

impl RegisterStep1Response {
    fn build(response: &RegistrationResponse) -> Result<Self> {
        Ok(Self {
            evaluated_element: response.evaluated_element,
            server_public_key: response.server_public_key,
            session_id: String::from(util::generate_session_key()),
        })
    }
}

impl Responder for RegisterStep1Response {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn register_step1(
    state: web::Data<Arc<AppState>>,
    data: web::Query<RegisterStep1Request>,
) -> Result<RegisterStep1Response> {
    if USERNAME_REGEX.captures(&data.username).is_none() {
        return Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            message: "Could not validate username".to_owned(),
            code: crate::error::ErrorCode::ValidationError,
            cause: None,
        });
    }

    let request = data.into_inner().try_into()?;
    let flow = ServerRegistrationFlow::new(&state.oprf_key, &state.ke_keypair.public_key);
    let response = flow.start(&request);
    let response = RegisterStep1Response::build(&response)?;

    let client = state.db.get().await?;
    let query = include_str!("../../db/queries/pending_registration_create.sql");
    let stmt = client.prepare(query).await?;

    let expiration_minutes = "5";
    client
        .query(
            &stmt,
            &[
                &response.session_id,
                &request.client_identity,
                &expiration_minutes,
            ],
        )
        .await
        .map_err(|e| Error {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: crate::error::ErrorCode::InternalError,
            message: "Could not create session".to_owned(),
            cause: Some(Cause::DbError(e)),
        })?;

    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub struct RegisterStep2Request {
    #[serde(with = "serialization::b64_envelope")]
    pub envelope: Envelope,
    #[serde(with = "serialization::b64_digest")]
    pub masking_key: Digest,
    #[serde(with = "serialization::b64_public_key")]
    pub client_public_key: PublicKey,
    #[serde(with = "serialization::b64_payload")]
    pub payload: KsfParams,
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterStep2Response {
    success: bool,
}

impl Responder for RegisterStep2Response {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn register_step2(
    state: web::Data<Arc<AppState>>,
    data: web::Json<RegisterStep2Request>,
) -> Result<RegisterStep2Response> {
    let mut client = state.db.get().await?;
    let txn = client.transaction().await?;

    // check & delete pending registration
    let stmt = include_str!("../../db/queries/pending_registration_drop.sql");
    let stmt = txn.prepare(stmt).await?;
    let result = txn.query(&stmt, &[&data.session_id]).await?;
    if result.is_empty() {
        return Err(Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::ValidationError,
            message: "could not find session".to_owned(),
            cause: None,
        });
    }
    let username: String = result.first().unwrap().get("username");

    // check & insert new user
    let stmt = include_str!("../../db/queries/user_create.sql");
    let stmt = txn.prepare(stmt).await?;
    txn.query(
        &stmt,
        &[
            &username,
            &util::b64_encode(&data.masking_key),
            &util::b64_encode(&data.client_public_key.serialize()),
            &util::b64_encode(&data.envelope.serialize()),
            &util::b64_encode(&data.payload.serialize()?),
        ],
    )
    .await
    .map_err(|e| Error {
        status: StatusCode::BAD_REQUEST.as_u16(),
        code: crate::error::ErrorCode::UsernameTakenError,
        message: format!("username '{}' is taken", username),
        cause: Some(Cause::DbError(e)),
    })?;

    txn.commit().await?;

    Ok(RegisterStep2Response { success: true })
}
