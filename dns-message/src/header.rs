use crate::{Message, MessageError, Result};
use std::default::Default;
use tracing::{instrument, trace};

#[derive(Debug, PartialEq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: OpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: RCode,
}

impl Header {
    #[instrument(skip(buf))]
    pub(crate) fn to_bytes(&self, message: &Message, buf: &mut Vec<u8>) -> Result<usize> {
        let mut pair = self.id.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);

        let mut val = 0u8;
        if self.qr {
            val |= 1 << 7;
        }
        val |= self.opcode.as_u8()? << 3;
        if self.aa {
            val |= 1 << 2;
        }
        if self.tc {
            val |= 1 << 1;
        }
        if self.rd {
            val |= 1;
        }
        buf.push(val);
        val = 0;
        if self.rd {
            val |= 1 << 7;
        }
        if self.ad {
            val |= 1 << 5;
        }
        if self.cd {
            val |= 1 << 4;
        }
        val |= self.rcode.as_u8();
        buf.push(val);

        pair = (message.questions.len() as u16).to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = (message.answers.len() as u16).to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = (message.name_servers.len() as u16).to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = (message.additional_records.len() as u16).to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);

        trace!("Wrote 12 bytes");

        Ok(12)
    }
}

#[derive(Debug, PartialEq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Unknown(u8),
}

impl OpCode {
    #[instrument]
    pub(crate) fn as_u8(&self) -> Result<u8> {
        match self {
            OpCode::Query => Ok(0),
            OpCode::IQuery => Ok(1),
            OpCode::Status => Ok(2),
            OpCode::Unknown(opcode) => {
                if *opcode > 0xf {
                    // OpCodes can only be 4 bits wide.
                    Err(MessageError::ReservedOpCode)
                } else {
                    Ok(*opcode)
                }
            }
        }
    }
}

impl Default for OpCode {
    fn default() -> Self {
        OpCode::Query
    }
}

#[derive(Debug, PartialEq)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl RCode {
    #[instrument]
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
            RCode::Unknown(i) => *i,
        }
    }
}

impl Default for RCode {
    fn default() -> Self {
        RCode::NoError
    }
}
