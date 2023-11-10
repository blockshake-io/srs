use blstrs::Scalar;
use config::Config;
use srs_opaque::{serialization, keypair::{PublicKey, SecretKey, KeyPair}};
use tokio_postgres::NoTls;

use srs::{
    models::KeyVersion,
    servers::indexer::{AppConfig, AppState, IndexerServer},
    Error, Result,
};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub srv_identity: String,
    pub srv_address: String,
    pub srv_port: u16,
    #[serde(with = "serialization::b64_public_key")]
    pub srv_ke_public_key: PublicKey,
    #[serde(with = "serialization::b64_secret_key")]
    pub srv_ke_private_key: SecretKey,
    pub srv_oprf_hosts: String,
    pub srv_oprf_threshold: u16,
    #[serde(with = "serialization::b64_scalar")]
    pub srv_username_oprf_key: Scalar,
    pub srv_fake_ksf_params: String,
    pub srv_default_key_version: KeyVersion,
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
            source: None,
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

    let ke_keypair = KeyPair {
        public_key: server_config.srv_ke_public_key,
        secret_key: server_config.srv_ke_private_key,
    };

    // the OPRF hosts environment variable is whitespace-separated string of hosts
    let oprf_hosts: Vec<String> = server_config
        .srv_oprf_hosts
        .split_ascii_whitespace()
        .map(|s| s.to_owned())
        .collect();

    let config = AppConfig {
        ke_keypair,
        oprf_hosts,
        oprf_threshold: server_config.srv_oprf_threshold,
        username_oprf_key: server_config.srv_username_oprf_key,
        version: server_config.srv_default_key_version,
    };

    let app_state = AppState {
        identity: server_config.srv_identity,
        db: db_config.create_pool(None, NoTls)?,
        redis: redis_client,
        fake_ksf_configs: serde_json::from_str(&server_config.srv_fake_ksf_params)?,
        configs: vec![config],
        default_version: server_config.srv_default_key_version,
    };

    IndexerServer::new(server_config.srv_address, server_config.srv_port, app_state)
        .run()
        .await
}
