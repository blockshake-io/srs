use blstrs::G2Affine;
use redis::Commands;
use regex::Regex;
use std::sync::Arc;

use crate::{
    constants::PENDING_REGISTRATION_TTL_SEC,
    error::Cause,
    redis::{ToRedisKey, NS_PENDING_REGISTRATION},
    session::SessionKey,
    session::SrsSession,
    util, AppState, Error, KsfParams, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use srs_opaque::{
    messages::{RegistrationRequest, RegistrationResponse, RegistrationRecord},
    opaque::ServerRegistrationFlow,
    payload::Payload,
};

lazy_static! {
    static ref USERNAME_REGEX: Regex =
        Regex::new(r"^[a-zA-Z0-9._+-]{3,32}(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$").unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingRegistration {
    username: String,
}

#[derive(Deserialize)]
pub struct RegisterStep1Request {
    pub username: String,
    #[serde(with = "srs_opaque::serialization::b64_g2")]
    pub blinded_element: G2Affine,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStep1Response {
    pub registration_response: RegistrationResponse,
    pub session_id: String,
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
    session: SrsSession,
    data: web::Json<RegisterStep1Request>,
) -> Result<RegisterStep1Response> {
    session.check_unauthenticated(&mut state.redis.get_connection()?)?;

    if USERNAME_REGEX.captures(&data.username).is_none() {
        return Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            message: "Could not validate username".to_owned(),
            code: crate::error::ErrorCode::ValidationError,
            cause: None,
        });
    }

    let request = RegistrationRequest {
        client_identity: data.username.clone(),
        blinded_element: data.blinded_element,
    };

    let flow = ServerRegistrationFlow::new(&state.oprf_key, &state.ke_keypair.public_key);
    let response = RegisterStep1Response {
        registration_response: flow.start(&request),
        session_id: SessionKey::random().to_str(),
    };

    // remember pending registration
    let pending_registration = serde_json::to_string(&PendingRegistration {
        username: data.username.clone(),
    })?;
    let mut client = state.redis.get_connection()?;
    client.set_ex(
        response.session_id.to_redis_key(NS_PENDING_REGISTRATION),
        pending_registration,
        PENDING_REGISTRATION_TTL_SEC,
    )?;

    Ok(response)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStep2Request {
    pub registration_record: RegistrationRecord<KsfParams>,
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

fn get_pending_registration(
    session_id: &str,
    redis: &redis::Client,
) -> Result<PendingRegistration> {
    let mut client = redis.get_connection()?;
    let pending_login: String = client.get_del(session_id.to_redis_key(NS_PENDING_REGISTRATION))?;
    let pending_login: PendingRegistration = serde_json::from_str(&pending_login)?;
    Ok(pending_login)
}

pub async fn register_step2(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Json<RegisterStep2Request>,
) -> Result<RegisterStep2Response> {
    session.check_unauthenticated(&mut state.redis.get_connection()?)?;

    // check & delete pending registration
    let pending_registration =
        get_pending_registration(&data.session_id, &state.redis).map_err(|_| Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::ValidationError,
            message: "could not find session".to_owned(),
            cause: None,
        })?;

    // check & insert new user
    let client = state.db.get().await?;
    let stmt = include_str!("../../db/queries/user_create.sql");
    let stmt = client.prepare(stmt).await?;
    client
        .query(
            &stmt,
            &[
                &pending_registration.username,
                &util::b64_encode(&data.registration_record.masking_key),
                &util::b64_encode(&data.registration_record.client_public_key.serialize()[..]),
                &util::b64_encode(&data.registration_record.envelope.serialize()),
                &util::b64_encode(&data.registration_record.payload.to_bytes()?[..]),
            ],
        )
        .await
        .map_err(|e| Error {
            status: StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::UsernameTakenError,
            message: format!("username '{}' is taken", &pending_registration.username),
            cause: Some(Cause::DbError(e)),
        })?;

    Ok(RegisterStep2Response { success: true })
}
