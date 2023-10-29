use config::Config;
use serde::Deserialize;
use srs::{
    servers::oracle::{AppState, OracleServer},
    Error, Result,
};

#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub srv_address: String,
    pub srv_port: u16,
    pub srv_default_key_version: u64,
    pub srv_secret_keys: String,
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
        .ok_or_else(|| Error::internal("Could not parse configuration variables"))?;

    let redis_client = redis::Client::open(config.redis_connection_string)?;

    let app_state = AppState {
        secret_keys: serde_json::from_str(&config.srv_secret_keys)?,
        default_key_version: config.srv_default_key_version,
        redis: redis_client,
    };

    OracleServer::new(config.srv_address, config.srv_port, app_state)
        .run()
        .await
}
