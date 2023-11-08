use std::{io::Write, fmt::Display};

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const KSF_BYTE_LEN: usize = 20;

#[derive(Debug, Serialize, Deserialize)]
pub struct KsfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: Option<usize>,
}

impl KsfParams {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::<u8>::with_capacity(20);
        buf.write_all(&self.m_cost.to_be_bytes()[..])?;
        buf.write_all(&self.t_cost.to_be_bytes()[..])?;
        buf.write_all(&self.p_cost.to_be_bytes()[..])?;
        buf.write_all(&self.output_len.unwrap_or(0).to_be_bytes()[..])?;
        Ok(buf)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if buf.len() != KSF_BYTE_LEN {
            return Err(Error::internal("Could not deserialize payload"));
        }

        let err = |_| Error::internal("Could not deserialize payload");
        let m_cost = u32::from_be_bytes(buf[0..4].try_into().map_err(err)?);
        let t_cost = u32::from_be_bytes(buf[4..8].try_into().map_err(err)?);
        let p_cost = u32::from_be_bytes(buf[8..12].try_into().map_err(err)?);
        let output_len = usize::from_be_bytes(buf[12..].try_into().map_err(err)?);
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

impl Display for KsfParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "(m_cost: {}, t_cost: {}, p_cost: {})",
            self.m_cost,
            self.t_cost,
            self.p_cost,
        ))
    }
}