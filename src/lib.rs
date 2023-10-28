#[macro_use]
extern crate lazy_static;

mod constants;
mod db;
pub mod error;
pub mod http;
pub mod ksf;
mod rate_limiter;
pub mod serialization;
pub mod servers;
pub mod services;
mod session;
pub mod util;
mod validators;

use serde::{Deserialize, Serialize};

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UserId(i64);
