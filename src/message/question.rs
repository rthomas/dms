use crate::message::{encode_str, Result};
use std::default::Default;
use std::fmt;

use tracing::{instrument, trace};
#[derive(Debug, PartialEq)]
pub struct Question {
    pub q_name: String,
    pub q_type: Type,
    pub q_class: Class,
}

impl Question {
    #[instrument(skip(buf))]
    pub(crate) fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut byte_count = encode_str(&self.q_name, buf)?;
        byte_count += self.q_type.to_bytes(buf);
        byte_count += self.q_class.to_bytes(buf);

        trace!("Wrote {} bytes", byte_count);

        Ok(byte_count)
    }
}

#[derive(Debug, PartialEq)]
pub enum Type {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AXFR,
    MAILB,
    MAILA,
    STAR,
    Unknown(u16),
}

impl Type {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> usize {
        let val = match self {
            Self::A => 1u16.to_be_bytes(),
            Self::NS => 2u16.to_be_bytes(),
            Self::MD => 3u16.to_be_bytes(),
            Self::MF => 4u16.to_be_bytes(),
            Self::CNAME => 5u16.to_be_bytes(),
            Self::SOA => 6u16.to_be_bytes(),
            Self::MB => 7u16.to_be_bytes(),
            Self::MG => 8u16.to_be_bytes(),
            Self::MR => 9u16.to_be_bytes(),
            Self::NULL => 10u16.to_be_bytes(),
            Self::WKS => 11u16.to_be_bytes(),
            Self::PTR => 12u16.to_be_bytes(),
            Self::HINFO => 13u16.to_be_bytes(),
            Self::MINFO => 14u16.to_be_bytes(),
            Self::MX => 15u16.to_be_bytes(),
            Self::TXT => 16u16.to_be_bytes(),
            Self::AXFR => 252u16.to_be_bytes(),
            Self::MAILB => 253u16.to_be_bytes(),
            Self::MAILA => 254u16.to_be_bytes(),
            Self::STAR => 255u16.to_be_bytes(),
            Self::Unknown(i) => i.to_be_bytes(),
        };
        buf.push(val[0]);
        buf.push(val[1]);

        trace!("Wrote 2 bytes");

        2
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        let disp = match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::MD => "MD",
            Self::MF => "MF",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::MB => "MB",
            Self::MG => "MG",
            Self::MR => "MR",
            Self::NULL => "NULL",
            Self::WKS => "WKS",
            Self::PTR => "PTR",
            Self::HINFO => "HINFO",
            Self::MINFO => "MINFO",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AXFR => "AXFR",
            Self::MAILB => "MAILB",
            Self::MAILA => "MAILA",
            Self::STAR => "*",
            Self::Unknown(i) => {
                write!(f, "Unknown({})", i)?;
                return Ok(());
            }
        };
        write!(f, "{}", disp)
    }
}

impl Default for Type {
    fn default() -> Self {
        Self::A
    }
}

impl From<Type> for u16 {
    fn from(t: Type) -> u16 {
        match t {
            Type::A => 1,
            Type::NS => 2,
            Type::MD => 3,
            Type::MF => 4,
            Type::CNAME => 5,
            Type::SOA => 6,
            Type::MB => 7,
            Type::MG => 8,
            Type::MR => 9,
            Type::NULL => 10,
            Type::WKS => 11,
            Type::PTR => 12,
            Type::HINFO => 13,
            Type::MINFO => 14,
            Type::MX => 15,
            Type::TXT => 16,
            Type::AXFR => 252,
            Type::MAILB => 253,
            Type::MAILA => 254,
            Type::STAR => 255,
            Type::Unknown(i) => i,
        }
    }
}

impl From<u16> for Type {
    #[instrument]
    fn from(val: u16) -> Self {
        match val {
            1 => Type::A,
            2 => Type::NS,
            3 => Type::MD,
            4 => Type::MF,
            5 => Type::CNAME,
            6 => Type::SOA,
            7 => Type::MB,
            8 => Type::MG,
            9 => Type::MR,
            10 => Type::NULL,
            11 => Type::WKS,
            12 => Type::PTR,
            13 => Type::HINFO,
            14 => Type::MINFO,
            15 => Type::MX,
            16 => Type::TXT,
            252 => Type::AXFR,
            253 => Type::MAILB,
            254 => Type::MAILA,
            255 => Type::STAR,
            _ => Type::Unknown(val),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Class {
    IN,
    CS,
    CH,
    HS,
    STAR,
    Unknown(u16),
}

impl Class {
    #[instrument(skip(buf))]
    pub(crate) fn to_bytes(&self, buf: &mut Vec<u8>) -> usize {
        let val = match self {
            Class::IN => 1u16.to_be_bytes(),
            Class::CS => 2u16.to_be_bytes(),
            Class::CH => 3u16.to_be_bytes(),
            Class::HS => 4u16.to_be_bytes(),
            Class::STAR => 255u16.to_be_bytes(),
            Class::Unknown(i) => i.to_be_bytes(),
        };
        buf.push(val[0]);
        buf.push(val[1]);

        trace!("Wrote 2 bytes");

        2
    }
}

impl Default for Class {
    fn default() -> Self {
        Class::IN
    }
}

impl From<u16> for Class {
    #[instrument]
    fn from(val: u16) -> Self {
        match val {
            1 => Class::IN,
            2 => Class::CS,
            3 => Class::CH,
            4 => Class::HS,
            255 => Class::STAR,
            _ => Class::Unknown(val),
        }
    }
}
