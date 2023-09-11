use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use blstrs::Scalar;
use config::Config;
use srs_opaque::primitives::derive_keypair;
use tokio_postgres::NoTls;

use srs_indexer::{
    error::ErrorCode::MissingParameterError,
    handlers::{registration::{register_step1, register_step2}, login::{login_step1, login_step2}},
    serialization, AppState, Error, Result,
};

use serde::Deserialize;
#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub srv_identity: String,
    pub srv_address: String,
    pub srv_port: u16,
    #[serde(with = "serialization::b64_scalar")]
    pub srv_oprf_key: Scalar,
    pub srv_ke_seed: String,
    pub srv_ke_info: String,
    pub db_user: Option<String>,
    pub db_password: Option<String>,
    pub db_host: Option<String>,
    pub db_name: Option<String>,
}

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let server_config: ServerConfig = Config::builder()
        .add_source(config::Environment::default())
        .build()
        .ok()
        .and_then(|c| c.try_deserialize().ok())
        .ok_or_else(|| Error {
            code: srs_indexer::error::ErrorCode::InternalError,
            cause: None,
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "Could not parse configuration variables".to_owned(),
        })?;

    let db_config = deadpool_postgres::Config {
        user: server_config.db_user,
        dbname: server_config.db_name,
        host: server_config.db_host,
        password: server_config.db_password,
        ..Default::default()
    };

    let ke_keypair = derive_keypair(
        server_config.srv_ke_seed.as_bytes(),
        server_config.srv_ke_info.as_bytes(),
    )?;

    let app_state = Arc::new(AppState {
        identity: server_config.srv_identity,
        ke_keypair,
        oprf_key: server_config.srv_oprf_key,
        db: db_config.create_pool(None, NoTls)?,
    });

    HttpServer::new(move || {
        // the QueryConfig & JsonConfig error handlers are callend when a
        // request cannot be parsed properly (e.g., because of a missing
        // parameter). in this case we return a bad request
        let query_cfg = web::QueryConfig::default().error_handler(|err, _req| {
            Error {
                status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                code: MissingParameterError,
                message: err.to_string(),
                cause: None,
            }
            .into()
        });
        let json_cfg = web::JsonConfig::default().error_handler(|err, _req| {
            Error {
                status: actix_web::http::StatusCode::BAD_REQUEST.as_u16(),
                code: MissingParameterError,
                message: err.to_string(),
                cause: None,
            }
            .into()
        });
        App::new()
            .app_data(query_cfg)
            .app_data(json_cfg)
            .app_data(web::Data::new(app_state.clone()))
            .service(
                web::scope("/api")
                    .route("register/step1", web::get().to(register_step1))
                    .route("register/step2", web::post().to(register_step2))
                    .route("login/step1", web::post().to(login_step1))
                    .route("login/step2", web::post().to(login_step2)),
            )
    })
    .bind((server_config.srv_address, server_config.srv_port))?
    .run()
    .await?;

    Ok(())
}
