use chrono::{Duration, NaiveDateTime, Utc};
use log::warn;
use rand::{seq::SliceRandom, thread_rng};
use redis::Commands;
use std::sync::Arc;

use crate::{
    constants::{PENDING_LOGIN_TTL_SEC, SESSION_TTL_SEC, USERNAME_OBFUSCATION},
    db,
    db::redis::{ToRedisKey, NS_PENDING_LOGIN},
    error::ErrorCode,
    models::{KeyVersion, User, UserId},
    servers::indexer::AppState,
    services::{oracle, rate_limiter},
    session::{SessionKey, SrsSession},
    util::crypto_rng_from_seed,
    validators::validate_username,
    Error, Result,
};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use srs_opaque::{
    ciphersuite::AuthCode,
    messages::{KeyExchange1, KeyExchange2, KeyExchange3, RegistrationRecord},
    opaque::{ServerLoginFlow, ServerLoginState},
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
    pub key_exchange: KeyExchange2,
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
    key_version: KeyVersion,
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
    // we validate the username to prevent, e.g., too long values to
    // be stored in redis for rate limiting
    validate_username(&data.username)?;

    // no session must be provided
    let mut redis_conn = state.redis.get_connection()?;
    session.check_unauthenticated(&mut redis_conn)?;

    // login attempts for a given username are rate-limited
    rate_limiter::check_rate_limit(&mut redis_conn, &data.username)?;

    // we fetch the user from the DB. if the user doesn't exist we create
    // a temporary fake user to prevent user enumeration attacks, see
    // the OPAQUE standard
    let user = match db::user::select_user_by_username(&state.db, &data.username).await {
        Ok(u) => u,
        Err(e) => match e.code {
            ErrorCode::MissingRecordError => {
                warn!(
                    "login-attempt for non-existing user '{}', using fake record",
                    data.username
                );
                create_fake_user(&data.username, &state)?
            }
            _ => return Err(e),
        },
    };

    let config = state.config_by_version(user.key_version)?;

    let rng = thread_rng();
    let client_identity = data.username.clone();
    let mut flow = ServerLoginFlow::new(
        &config.ke_keypair.public_key,
        Some(&state.identity),
        &config.ke_keypair,
        &user.registration_record,
        &data.key_exchange,
        &client_identity,
        rng,
    );

    let evaluated_element = oracle::blind_evaluate(
        state.get_ref().as_ref(),
        &data.key_exchange.credential_request.blinded_element,
        oracle::obfuscate_username(&data.username, &config.username_oprf_key)?,
        config.version,
    )
    .await?;

    let (login_state, ke2) = flow.start(evaluated_element)?;
    let response = LoginStep1Response {
        key_exchange: ke2,
        session_id: SessionKey::random().to_str(),
    };

    let pending_login = serde_json::to_string(&PendingLogin {
        user_id: user.id,
        key_version: user.key_version,
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
    #[serde(with = "crate::serialization::iso8601")]
    pub session_expiration: NaiveDateTime,
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
        source: None,
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
        source: Some(crate::error::Source::OpaqueError(e)),
    })?;

    let session_ttl = Duration::seconds(SESSION_TTL_SEC);
    let session_expiration = Utc::now().naive_utc() + session_ttl;
    let session = SrsSession::create(
        &mut state.redis.get_connection()?,
        pending_login.user_id,
        pending_login.key_version,
        &session_ttl,
    )?;
    Ok(LoginStep2Response {
        session_key: session.key,
        session_expiration,
    })
}

fn create_fake_user(username: &str, state: &AppState) -> Result<User> {
    let config = state.default_config();
    let mut rng = crypto_rng_from_seed(
        &srs_opaque::oprf::evaluate(
            username.as_bytes(),
            USERNAME_OBFUSCATION,
            &config.username_oprf_key,
        )?[..],
    );
    let fake_ksf = state
        .fake_ksf_configs
        .choose(&mut rng)
        .ok_or_else(|| Error {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: ErrorCode::InternalError,
            message: "No default KSF parameters found".to_owned(),
            source: None,
        })?;
    let record = RegistrationRecord::fake(&mut rng, fake_ksf.to_bytes()?.clone());
    Ok(User {
        id: UserId(0),
        key_version: config.version,
        registration_record: record,
    })
}
