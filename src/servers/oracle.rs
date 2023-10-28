use std::sync::Arc;

use blstrs::Scalar;

use crate::{
    error::ErrorCode::DeserializationError, http::oracle::blind_evaluate::blind_evaluate_endpoint,
    Error, Result,
};
use actix_web::{
    middleware::{ErrorHandlers, Logger},
    web, App, HttpServer,
};

use super::error_logger;

pub struct AppState {
    pub secret_key_share: Scalar,
    pub secret_key_index: u64,
    pub redis: ::redis::Client,
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
                .service(
                    web::scope("/api")
                        .route("blind-evaluate", web::post().to(blind_evaluate_endpoint)),
                )
        })
        .bind((srv_address, self.srv_port))?
        .run()
        .await?;

        Ok(())
    }
}
