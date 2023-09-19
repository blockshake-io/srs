use chrono::{Duration, FixedOffset, Utc};
use rand::thread_rng;
use redis::Commands;
use std::sync::Arc;

use crate::{
    constants::{PENDING_LOGIN_TTL_SEC, SESSION_TTL_SEC},
    db,
    redis::{ToRedisKey, NS_PENDING_LOGIN},
    session::{SessionKey, SrsSession},
    AppState, Error, KsfParams, Result, UserId,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use srs_opaque::{
    messages::{KeyExchange1, KeyExchange2, KeyExchange3},
    opaque::{ServerLoginFlow, ServerLoginState}, ciphersuite::AuthCode,
    serialization,
};

#[derive(Serialize, Deserialize)]
pub struct LoginStep1Request {
    pub username: String,
    pub key_exchange: KeyExchange1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStep1Response {
    pub session_id: String,
    pub key_exchange: KeyExchange2<KsfParams>,
}

impl Responder for LoginStep1Response {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingLogin {
    user_id: UserId,
    username: String,
    #[serde(with = "serialization::b64_auth_code")]
    session_key: AuthCode,
    #[serde(with = "serialization::b64_auth_code")]
    expected_client_mac: AuthCode,
}

pub async fn login_step1(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Json<LoginStep1Request>,
) -> Result<LoginStep1Response> {
    session.check_unauthenticated(&mut state.redis.get_connection()?)?;

    // TODO here we might want to return a dummy record
    let user = db::select_user_by_username(&state.db, &data.username)
        .await
        .map_err(|_| Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::MissingRecordError,
            message: "Could not find record".to_owned(),
            cause: None,
        })?;

    let rng = thread_rng();
    let client_identity = data.username.clone();
    let mut flow = ServerLoginFlow::new(
        &state.ke_keypair.public_key,
        Some(&state.identity),
        &state.ke_keypair,
        &user.registration_record,
        &state.oprf_key,
        &data.key_exchange,
        &client_identity,
        rng,
    );

    let (login_state, ke2) = flow.start()?;
    let response = LoginStep1Response {
        key_exchange: ke2,
        session_id: SessionKey::random().to_str(),
    };

    let pending_login = serde_json::to_string(&PendingLogin {
        user_id: user.id,
        username: data.username.clone(),
        session_key: login_state.session_key,
        expected_client_mac: login_state.expected_client_mac,
    })?;
    let mut client = state.redis.get_connection()?;
    client.set_ex(
        response.session_id.to_redis_key(NS_PENDING_LOGIN),
        pending_login,
        PENDING_LOGIN_TTL_SEC,
    )?;

    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub struct LoginStep2Request {
    pub session_id: String,
    pub key_exchange: KeyExchange3,
}

#[derive(Serialize, Deserialize)]
pub struct LoginStep2Response {
    pub session_key: SessionKey,
    #[serde(with = "crate::serialization::rfc33339")]
    pub session_expiration: chrono::DateTime<FixedOffset>,
}

impl Responder for LoginStep2Response {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

fn get_pending_login(session_id: &str, redis: &redis::Client) -> Result<PendingLogin> {
    let mut client = redis.get_connection()?;
    let pending_login: String = client.get_del(session_id.to_redis_key(NS_PENDING_LOGIN))?;
    let pending_login: PendingLogin = serde_json::from_str(&pending_login)?;
    Ok(pending_login)
}

pub async fn login_step2(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
    data: web::Json<LoginStep2Request>,
) -> Result<LoginStep2Response> {
    session.check_unauthenticated(&mut state.redis.get_connection()?)?;

    let pending_login = get_pending_login(&data.session_id, &state.redis).map_err(|_| Error {
        status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
        code: crate::error::ErrorCode::ValidationError,
        message: "could not find session".to_owned(),
        cause: None,
    })?;

    let flow = ServerLoginState {
        session_key: pending_login.session_key,
        expected_client_mac: pending_login.expected_client_mac,
    };

    // finalizes authorization
    flow.finish(&data.key_exchange).map_err(|e| Error {
        status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
        message: "Could not authorize user".to_owned(),
        code: crate::error::ErrorCode::DeserializationError,
        cause: Some(crate::error::Cause::OpaqueError(e)),
    })?;

    let session_ttl = Duration::seconds(SESSION_TTL_SEC);
    let session_expiration =
        Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap()) + session_ttl;
    let session = SrsSession::create(
        &mut state.redis.get_connection()?,
        &pending_login.user_id,
        &session_ttl,
    )?;
    Ok(LoginStep2Response {
        session_key: session.key,
        session_expiration,
    })
}

#[derive(Serialize, Deserialize)]
pub struct LoginTestResponse {
    body: String,
}

impl Responder for LoginTestResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(self.body)
    }
}

pub async fn login_test(
    state: web::Data<Arc<AppState>>,
    session: SrsSession,
) -> Result<LoginTestResponse> {
    session.check_authenticated(&mut state.redis.get_connection()?)?;
    Ok(LoginTestResponse {
        body: "success".to_owned(),
    })
}
