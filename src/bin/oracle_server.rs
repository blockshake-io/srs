use blstrs::Scalar;
use config::Config;
use serde::Deserialize;
use srs::{
    error::ErrorCode,
    servers::oracle::{AppState, OracleServer},
    Error, Result,
};
use srs_opaque::serialization;

#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub srv_address: String,
    pub srv_port: u16,
    pub srv_secret_key_index: u64,
    #[serde(with = "serialization::b64_scalar")]
    pub srv_secret_key_share: Scalar,
    pub redis_connection_string: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    // initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // read environment variables
    dotenv::dotenv().ok();
    let config: ServerConfig = Config::builder()
        .add_source(config::Environment::default())
        .build()
        .ok()
        .and_then(|c| c.try_deserialize().ok())
        .ok_or_else(|| Error {
            code: ErrorCode::InternalError,
            source: None,
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "Could not parse configuration variables".to_owned(),
        })?;

    let redis_client = redis::Client::open(config.redis_connection_string)?;

    let app_state = AppState {
        secret_key_share: config.srv_secret_key_share,
        secret_key_index: config.srv_secret_key_index,
        redis: redis_client,
    };

    OracleServer::new(config.srv_address, config.srv_port, app_state)
        .run()
        .await
}
