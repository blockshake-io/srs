#[macro_use]
extern crate lazy_static;

use blstrs::Scalar;
use generic_array::GenericArray;
use serde::{Serialize, Deserialize};
use srs_opaque::{keypair::KeyPair, payload::Payload};
use typenum::{U20, U4, U8};

mod db;
mod session;
pub mod error;
pub mod handlers;
pub mod serialization;
pub mod util;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserId(u64);

pub struct AppState {
    pub identity: String,
    pub oprf_key: Scalar,
    pub ke_keypair: KeyPair,
    pub db: deadpool_postgres::Pool,
    pub redis: redis::Client,
}

#[derive(Debug, Copy, Clone)]
pub struct KsfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: Option<usize>,
}

impl Payload for KsfParams {
    type Len = U20;

    fn serialize(
        &self,
    ) -> std::result::Result<GenericArray<u8, Self::Len>, srs_opaque::error::Error> {
        use generic_array::sequence::Concat;
        let mut m_cost = GenericArray::<u8, U4>::default();
        let mut t_cost = GenericArray::<u8, U4>::default();
        let mut p_cost = GenericArray::<u8, U4>::default();
        let mut output_len = GenericArray::<u8, U8>::default();
        m_cost.copy_from_slice(&self.m_cost.to_be_bytes()[..]);
        t_cost.copy_from_slice(&self.t_cost.to_be_bytes()[..]);
        p_cost.copy_from_slice(&self.p_cost.to_be_bytes()[..]);
        output_len.copy_from_slice(&self.output_len.unwrap_or(0).to_be_bytes()[..]);
        Ok(m_cost.concat(t_cost).concat(p_cost).concat(output_len))
    }

    fn deserialize(
        buf: &GenericArray<u8, Self::Len>,
    ) -> std::result::Result<Self, srs_opaque::error::Error>
    where
        Self: Sized,
    {
        let m_cost = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let t_cost = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let p_cost = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let output_len = usize::from_be_bytes(buf[12..].try_into().unwrap());
        Ok(KsfParams {
            m_cost,
            t_cost,
            p_cost,
            output_len: if output_len == 0 {
                None
            } else {
                Some(output_len)
            },
        })
    }
}
