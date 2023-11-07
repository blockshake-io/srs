use std::sync::Arc;

use blstrs::Scalar;
use srs_opaque::keypair::KeyPair;

use actix_web::{
    middleware::{ErrorHandlers, Logger},
    web, App, HttpServer,
};

use crate::{
    error::ErrorCode::DeserializationError,
    http::indexer::{
        authenticate::{authenticate_step1, authenticate_step2},
        blind_evaluate::blind_evaluate,
        cipher_data::{download_cipher_data, get_cipher_data, post_cipher_data},
        logout::logout,
        registration::{register_step1, register_step2},
    },
    ksf::KsfParams,
    models::KeyVersion,
    Error, Result,
};

use super::error_logger;

pub struct AppConfig {
    pub version: KeyVersion,
    pub ke_keypair: KeyPair,
    pub oprf_hosts: Vec<String>,
    pub oprf_threshold: u16,
    pub username_oprf_key: Scalar,
}

pub struct AppState {
    pub identity: String,
    pub db: deadpool_postgres::Pool,
    pub redis: redis::Client,
    pub configs: Vec<AppConfig>,
    pub default_version: KeyVersion,
    pub fake_ksf_configs: Vec<KsfParams>,
}

impl AppState {
    pub fn config_by_version(&self, version: KeyVersion) -> Result<&AppConfig> {
        self.configs
            .iter()
            .find(|c| c.version == version)
            .ok_or_else(|| Error {
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                code: crate::error::ErrorCode::InternalError,
                message: "version not supported".to_owned(),
                source: None,
            })
    }

    pub fn default_config(&self) -> &AppConfig {
        self.config_by_version(self.default_version)
            .expect("no config for default version given")
    }
}

pub struct IndexerServer {
    srv_address: String,
    srv_port: u16,
    app_state: Arc<AppState>,
}

impl IndexerServer {
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
            // the QueryConfig & JsonConfig error handlers are callend when a
            // request cannot be parsed properly (e.g., because of a missing
            // parameter). in this case we return a bad request
            let query_cfg = web::QueryConfig::default().error_handler(|err, _req| {
                Error {
                    status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                    code: DeserializationError,
                    message: err.to_string(),
                    source: None,
                }
                .into()
            });
            let json_cfg = web::JsonConfig::default().error_handler(|err, _req| {
                Error {
                    status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                    code: DeserializationError,
                    message: err.to_string(),
                    source: None,
                }
                .into()
            });
            App::new()
                .app_data(query_cfg)
                .app_data(json_cfg)
                .app_data(web::Data::new(app_state.clone()))
                .wrap(Logger::new("\"%r\" %s %D"))
                .wrap(ErrorHandlers::new().default_handler(error_logger))
                .service(
                    web::scope("/api")
                        .route("accounts/register/step1", web::post().to(register_step1))
                        .route("accounts/register/step2", web::post().to(register_step2))
                        .route(
                            "accounts/authenticate/step1",
                            web::post().to(authenticate_step1),
                        )
                        .route(
                            "accounts/authenticate/step2",
                            web::post().to(authenticate_step2),
                        )
                        .route("accounts/logout", web::get().to(logout))
                        .route("cipher-data", web::post().to(post_cipher_data))
                        .route("cipher-data", web::get().to(get_cipher_data))
                        .route(
                            "cipher-data/{id}/download",
                            web::get().to(download_cipher_data),
                        )
                        .route("oprf/blind-evaluate", web::post().to(blind_evaluate)),
                )
        })
        .bind((srv_address, self.srv_port))?
        .run()
        .await?;

        Ok(())
    }
}
