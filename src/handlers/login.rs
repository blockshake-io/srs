use blstrs::{G2Affine, Gt};
use rand::thread_rng;
use std::sync::Arc;

use crate::{db, AppState, Error, Result, serialization, KsfParams, util, error::Cause};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use srs_opaque::{
    messages::{AuthRequest, CredentialRequest, KeyExchange1, KeyExchange2, KeyExchange3},
    opaque::ServerLoginFlow, ciphersuite::{Nonce, Bytes, LenMaskedResponse, AuthCode}, keypair::PublicKey,
};

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
            session_id: String::from(util::generate_session_key()),
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

pub async fn login_step1(
    state: web::Data<Arc<AppState>>,
    data: web::Json<LoginStep1Request>,
) -> Result<LoginStep1Response> {
    // TODO here we might want to return a dummy record
    let record = db::select_record(&state.db, &data.username)
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
    let session_key = util::b64_encode(flow.session_key().as_ref().unwrap());
    let expected_client_mac = util::b64_encode(flow.expected_client_mac().as_ref().unwrap());

    let client = state.db.get().await?;
    let query = include_str!("../../db/queries/pending_logins_create.sql");
    let stmt = client.prepare(query).await?;

    let expiration_minutes = "5";
    client
        .query(
            &stmt,
            &[
                &response.session_id,
                &username,
                &session_key,
                &expected_client_mac,
                &expiration_minutes,
            ],
        )
        .await
        .map_err(|e| Error {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            code: crate::error::ErrorCode::InternalError,
            message: "Could not create session".to_owned(),
            cause: Some(Cause::DbError(e)),
        })?;

    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub struct LoginStep2Request {
    pub session_id: String,
    #[serde(with = "serialization::b64_auth_code")]
    pub client_mac: AuthCode,
}

#[derive(Serialize, Deserialize)]
pub struct LoginStep2Response {
    success: bool,
}

impl Responder for LoginStep2Response {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(serde_json::to_string(&self).unwrap())
    }
}

pub async fn login_step2(
    state: web::Data<Arc<AppState>>,
    data: web::Json<LoginStep2Request>,
) -> Result<LoginStep2Response> {
    let client = state.db.get().await?;

    // check & delete pending registration
    let stmt = include_str!("../../db/queries/pending_logins_drop.sql");
    let stmt = client.prepare(stmt).await?;
    let result = client.query(&stmt, &[&data.session_id]).await?;
    if result.is_empty() {
        return Err(Error {
            status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
            code: crate::error::ErrorCode::ValidationError,
            message: "could not find session".to_owned(),
            cause: None,
        });
    }
    let expected_client_mac: String = result.first().unwrap().get("expected_client_mac");
    let expected_client_mac = serialization::b64_auth_code::decode(&expected_client_mac)?;

    let ke3 = KeyExchange3 {
        client_mac: data.client_mac,
    };

    if ke3.client_mac == expected_client_mac {
        Ok(LoginStep2Response { success: true })
    } else {
        Err(Error {
            status: actix_web::http::StatusCode::UNAUTHORIZED.as_u16(),
            message: "Could not authorize user".to_owned(),
            code: crate::error::ErrorCode::DeserializationError,
            cause: None,
        })
    }
}