use blstrs::{G2Affine, Gt};
use rand::thread_rng;
use redis::Commands;
use std::sync::Arc;

use crate::{db, AppState, Error, Result, serialization, KsfParams, session::{SrsSession, SessionKey}, UserId};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use srs_opaque::{
    messages::{AuthRequest, CredentialRequest, KeyExchange1, KeyExchange2, KeyExchange3},
    opaque::ServerLoginFlow, ciphersuite::{Nonce, Bytes, LenMaskedResponse, AuthCode}, keypair::PublicKey,
};

const PENDING_LOGIN_TTL_SEC: usize = 60;

#[derive(Serialize, Deserialize)]
pub struct LoginStep1Request {
    pub username: String,
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
    #[serde(with = "serialization::b64_nonce")]
    pub client_nonce: Nonce,
    #[serde(with = "serialization::b64_public_key")]
    pub client_public_keyshare: PublicKey,
}

impl TryInto<KeyExchange1> for LoginStep1Request {
    type Error = Error;

    fn try_into(self) -> Result<KeyExchange1> {
        Ok(KeyExchange1 {
            credential_request: CredentialRequest {
                blinded_element: self.blinded_element,
            },
            auth_request: AuthRequest {
                client_nonce: self.client_nonce,
                client_public_keyshare: self.client_public_keyshare,
            },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct _CredentialResponse {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    #[serde(with = "serialization::b64_nonce")]
    pub masking_nonce: Nonce,
    #[serde(with = "serialization::b64_masked_response")]
    pub masked_response: Bytes<LenMaskedResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct _AuthResponse {
    #[serde(with = "serialization::b64_nonce")]
    pub server_nonce: Nonce,
    #[serde(with = "serialization::b64_public_key")]
    pub server_public_keyshare: PublicKey,
    #[serde(with = "serialization::b64_auth_code")]
    pub server_mac: AuthCode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStep1Response {
    pub credential_response: _CredentialResponse,
    pub auth_response: _AuthResponse,
    #[serde(with = "serialization::b64_payload")]
    pub payload: KsfParams,
    pub session_id: String,
}

impl LoginStep1Response {
    fn build(ke2: &KeyExchange2<KsfParams>) -> Self {
        Self {
            credential_response: _CredentialResponse {
                evaluated_element: ke2.credential_response.evaluated_element,
                masking_nonce: ke2.credential_response.masking_nonce,
                masked_response: ke2.credential_response.masked_response,
            },
            auth_response: _AuthResponse {
                server_nonce: ke2.auth_response.server_nonce,
                server_public_keyshare: ke2.auth_response.server_public_keyshare,
                server_mac: ke2.auth_response.server_mac,
            },
            payload: ke2.payload,
            session_id: SessionKey::random().to_str(),
        }
    }
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
    data: web::Json<LoginStep1Request>,
) -> Result<LoginStep1Response> {
    // TODO here we might want to return a dummy record
    let (user_id, record) = db::select_record(&state.db, &data.username)
        .await
        .map_err(|_| Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::MissingRecordError,
            message: "Could not find record".to_owned(),
            cause: None,
        })?;

    let username = data.username.clone();
    let ke1: KeyExchange1 = data.into_inner().try_into()?;

    let rng = thread_rng();
    let mut flow = ServerLoginFlow::new(
        &state.ke_keypair.public_key,
        Some(&state.identity),
        &state.ke_keypair,
        &record,
        &state.oprf_key,
        &ke1,
        &username,
        rng,
    );

    let ke2 = flow.start()?;
    let response = LoginStep1Response::build(&ke2);

    let pending_login = serde_json::to_string(&PendingLogin {
        user_id,
        username: username.clone(),
        session_key: flow.session_key().unwrap(),
        expected_client_mac: flow.expected_client_mac().unwrap(),
    })?;
    let mut client = state.redis.get_connection()?;
    client.set_ex(response.session_id.clone(), pending_login, PENDING_LOGIN_TTL_SEC)?;

    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub struct LoginStep2Request {
    pub session_id: String,
    #[serde(with = "serialization::b64_auth_code")]
    pub client_mac: AuthCode,
}

// TODO: should we add an expiration date to this token?
// see https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
#[derive(Serialize, Deserialize)]
pub struct LoginStep2Response {
    pub session_key: String,
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
    let pending_login: String = client.get_del(session_id)?;
    let pending_login: PendingLogin = serde_json::from_str(&pending_login)?;
    Ok(pending_login)
}

pub async fn login_step2(
    state: web::Data<Arc<AppState>>,
    data: web::Json<LoginStep2Request>,
) -> Result<LoginStep2Response> {
    let pending_login = get_pending_login(&data.session_id, &state.redis).map_err(|_|
        Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::ValidationError,
            message: "could not find session".to_owned(),
            cause: None,
    })?;

    let ke3 = KeyExchange3 {
        client_mac: data.client_mac,
    };

    // TODO: here we should call flow.finish
    if ke3.client_mac == pending_login.expected_client_mac {
        let session = SrsSession::create(&pending_login.user_id, &mut state.redis.get_connection()?)?;
        Ok(LoginStep2Response { session_key: session.key().unwrap().to_str() })
    } else {
        Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            message: "Could not authorize user".to_owned(),
            code: crate::error::ErrorCode::DeserializationError,
            cause: None,
        })
    }
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
    if session.is_authenticated(&mut state.redis.get_connection()?) {
        Ok(LoginTestResponse { body: "success".to_owned() })
    } else {
        Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            code: crate::error::ErrorCode::AuthenticationError,
            message: "User not authenticated".to_owned(),
            cause: None,
        })
    }
}