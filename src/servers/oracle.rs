use actix_web::{
    middleware::{ErrorHandlers, Logger},
    web, App, HttpServer,
};
use blstrs::Scalar;
use serde::{Deserialize, Serialize};
use srs_opaque::serialization;
use std::sync::Arc;

use crate::{
    error::ErrorCode::DeserializationError, http::oracle::blind_evaluate::blind_evaluate, Error,
    Result,
};

use super::error_logger;

/// A `SecretKey` represents a point on a polynomial that is used for
/// Shamir's secret sharing (SSS) scheme. If the Oracle is not used
/// as part of a SSS cluster, the x-coordinate of the point can be
/// ignored and only the y-coordinate is relevant.
///
/// They key has a version to allow the Oracle to serve multiple keys
/// at once. This can be relevant if a particular key is compromised
/// and a new key needs to be used.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey {
    pub version: u64,
    /// The `index` is the x-coordinate of the point on the polynomial
    pub index: u64,
    /// The `share` is the y-coordinate of the point on the polynomial
    #[serde(with = "serialization::b64_scalar")]
    pub share: Scalar,
}

pub struct AppState {
    pub secret_keys: Vec<SecretKey>,
    pub default_key_version: u64,
    pub redis: redis::Client,
}

impl AppState {
    pub fn secret_by_version(&self, version: u64) -> Option<&SecretKey> {
        self.secret_keys.iter().find(|s| s.version == version)
    }
}

pub struct OracleServer {
    srv_address: String,
    srv_port: u16,
    app_state: Arc<AppState>,
}

impl OracleServer {
    pub fn new(srv_address: String, srv_port: u16, state: AppState) -> Self {
        Self {
            srv_address,
            srv_port,
            app_state: Arc::new(state),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let app_state = self.app_state.clone();
        let srv_address = self.srv_address.clone();
        HttpServer::new(move || {
            let json_cfg = web::JsonConfig::default().error_handler(|err, _| {
                Error {
                    status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                    code: DeserializationError,
                    message: err.to_string(),
                    source: None,
                }
                .into()
            });
            App::new()
                .app_data(web::Data::new(app_state.clone()))
                .app_data(json_cfg)
                .wrap(Logger::new("\"%r\" %s %D"))
                .wrap(ErrorHandlers::new().default_handler(error_logger))
                .service(web::scope("/api").route("blind-evaluate", web::post().to(blind_evaluate)))
        })
        .bind((srv_address, self.srv_port))?
        .run()
        .await?;

        Ok(())
    }
}
