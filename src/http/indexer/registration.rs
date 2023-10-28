use blstrs::G2Affine;
use redis::Commands;
use std::sync::Arc;

use crate::{
    constants::PENDING_REGISTRATION_TTL_SEC,
    db,
    db::redis::{ToRedisKey, NS_PENDING_REGISTRATION},
    ksf::KsfParams,
    servers::indexer::AppState,
    services::oracle,
    session::SessionKey,
    session::SrsSession,
    validators::validate_username,
    Error, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use srs_opaque::{
    messages::{RegistrationRecord, RegistrationResponse},
    opaque::ServerRegistrationFlow,
};

#[derive(Debug, Serialize, Deserialize)]
struct PendingRegistration {
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    validate_username(&data.username)?;

    let flow = ServerRegistrationFlow::new(&state.ke_keypair.public_key);
    let evaluated_element = oracle::blind_evaluate(
        state.get_ref().as_ref(),
        &data.blinded_element,
        oracle::obfuscate_username(&data.username, &state.username_oprf_key)?,
    )
    .await?;
    let registration_response = flow.start(evaluated_element);

    let response = RegisterStep1Response {
        registration_response,
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
            source: None,
        })?;

    // TODO: should we slow down the the request if the username is taken
    // to prevent user enumeration attacks?

    // check & insert new user
    db::user::insert_user(
        &state.db,
        &pending_registration.username,
        &data.registration_record,
    )
    .await?;

    Ok(RegisterStep2Response { success: true })
}
