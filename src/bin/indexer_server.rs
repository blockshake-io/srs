use blstrs::Scalar;
use config::Config;
use srs_opaque::{primitives::derive_keypair, serialization};
use tokio_postgres::NoTls;

use srs::{
    servers::indexer::{AppState, IndexerServer},
    Error, Result,
};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub srv_identity: String,
    pub srv_address: String,
    pub srv_port: u16,
    pub srv_ke_seed: String,
    pub srv_ke_info: String,
    pub srv_oprf_hosts: String,
    pub srv_oprf_threshold: u16,
    #[serde(with = "serialization::b64_scalar")]
    pub srv_username_oprf_key: Scalar,
    pub srv_fake_ksf_params: String,
    pub db_user: Option<String>,
    pub db_password: Option<String>,
    pub db_host: Option<String>,
    pub db_name: Option<String>,
    pub redis_connection_string: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    // initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // read environment variables
    dotenv::dotenv().ok();
    let server_config: ServerConfig = Config::builder()
        .add_source(config::Environment::default())
        .build()
        .ok()
        .and_then(|c| c.try_deserialize().ok())
        .ok_or_else(|| Error {
            code: srs::error::ErrorCode::InternalError,
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

    let redis_client = redis::Client::open(server_config.redis_connection_string)?;

    let ke_keypair = derive_keypair(
        server_config.srv_ke_seed.as_bytes(),
        server_config.srv_ke_info.as_bytes(),
    )?;

    // the OPRF hosts environment variable is whitespace-separated string of hosts
    let oprf_hosts: Vec<String> = server_config
        .srv_oprf_hosts
        .split_ascii_whitespace()
        .map(|s| s.to_owned())
        .collect();

    let app_state = AppState {
        identity: server_config.srv_identity,
        oprf_hosts,
        oprf_threshold: server_config.srv_oprf_threshold,
        ke_keypair,
        db: db_config.create_pool(None, NoTls)?,
        redis: redis_client,
        username_oprf_key: server_config.srv_username_oprf_key,
        fake_ksf_configs: serde_json::from_str(&server_config.srv_fake_ksf_params)?,
    };

    IndexerServer::new(server_config.srv_address, server_config.srv_port, app_state)
        .run()
        .await
}
