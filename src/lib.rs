#[macro_use]
extern crate lazy_static;

mod constants;
mod db;
mod distributed_oprf;
pub mod error;
pub mod handlers;
pub mod ksf;
mod rate_limiter;
mod redis;
pub mod serialization;
pub mod servers;
mod session;
pub mod util;
mod validators;

use serde::{Deserialize, Serialize};

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UserId(i64);
