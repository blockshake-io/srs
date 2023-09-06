use regex::Regex;
use std::sync::Arc;

use crate::{error::Cause, util, AppState, Error, Result};
use actix_web::{
    body::BoxBody, http::header::ContentType, web, HttpRequest, HttpResponse, Responder,
};
use blstrs::G2Affine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use srs_opaque::{
    ciphersuite::{LenHash, LenKePublicKey},
    keypair::PublicKey,
    messages::{RegistrationRequest, RegistrationResponse},
    opaque::ServerRegistrationFlow,
};
use typenum::U96;

lazy_static! {
    static ref USERNAME_REGEX: Regex =
        Regex::new(r"^[a-zA-Z0-9._+-]{3,32}(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?$").unwrap();
}

#[derive(Deserialize)]
pub struct RegisterStep1Request {
    pub username: String,
    pub blinded_element: String,
}

impl TryInto<RegistrationRequest> for RegisterStep1Request {
    type Error = Error;

    fn try_into(self) -> Result<RegistrationRequest> {
        let blinded_element = util::b64_decode::<U96>(&self.blinded_element)
            .ok()
            .and_then(|data| {
                let buf: &[u8; 96] = data[..].try_into().unwrap();
                G2Affine::from_compressed(buf).into()
            })
            .ok_or_else(|| Self::Error {
                status: StatusCode::BAD_REQUEST.as_u16(),
                code: crate::error::ErrorCode::ValidationError,
                message: "could not parse blinded_element".to_owned(),
                cause: None,
            })?;

        Ok(RegistrationRequest {
            blinded_element,
            client_identity: self.username,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStep1Response {
    pub evaluated_element: String,
    pub server_public_key: String,
    pub session_id: String,
}

impl RegisterStep1Response {
    fn build(response: &RegistrationResponse) -> Result<Self> {
        let evaluated_element = util::b64_encode_gt(&response.evaluated_element)?;
        let server_public_key = util::b64_encode_public_key(&response.server_public_key);
        let session_id = String::from(util::generate_session_key());
        Ok(Self {
            evaluated_element,
            server_public_key,
            session_id,
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
    let flow = ServerRegistrationFlow::new(&state.oprf_key, &state.server_public_key);
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
    pub envelope: String,
    pub masking_key: String,
    pub client_public_key: String,
    pub payload: String,
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
    // make sure that masking_key and client_public_key are valid
    util::b64_decode::<LenHash>(&data.masking_key)?;
    PublicKey::deserialize(&util::b64_decode::<LenKePublicKey>(
        &data.client_public_key,
    )?)?;

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
            &data.masking_key,
            &data.client_public_key,
            &data.envelope,
            &data.payload,
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
