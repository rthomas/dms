use crate::message::{encode_str, Class, Result};
use std::fmt;
use std::net::Ipv4Addr;
use tracing::{instrument, trace};

#[derive(Debug, PartialEq)]
pub struct ResourceRecord {
    pub name: String,
    pub r_type: RData,
    pub class: Class,
    pub ttl: u32,
}

impl ResourceRecord {
    #[instrument(skip(buf))]
    pub(crate) fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        // TODO here is where we would implement the Message Compression -
        // though we will need to wire through a map of the strings and
        // locations. It is perfectly fine with the spec to not implement this.
        let mut byte_count = encode_str(&self.name, buf)?;
        byte_count += self.r_type.to_bytes_type(buf);
        byte_count += self.class.to_bytes(buf);

        let ttl = self.ttl.to_be_bytes();
        buf.push(ttl[0]);
        buf.push(ttl[1]);
        buf.push(ttl[2]);
        buf.push(ttl[3]);
        byte_count += 4;

        // We need this temp (rdata) buffer here as we don't know how long the
        // rdata will be until we convert it to bytes. We need this to get the
        // length of it, before we write the length.
        let mut rdata: Vec<u8> = Vec::with_capacity(255);
        let rdlength = self.r_type.to_bytes(&mut rdata)?;
        byte_count += rdlength;

        let rdlength = (rdlength as u16).to_be_bytes();
        buf.push(rdlength[0]);
        buf.push(rdlength[1]);
        byte_count += 2;
        buf.extend(rdata);

        trace!("Wrote {} bytes", byte_count);

        Ok(byte_count)
    }
}

#[derive(Debug, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    NS,
    MD,
    MF,
    CNAME(String),
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
    Raw(u16, Vec<u8>),
}

impl RData {
    #[instrument(skip(buf))]
    fn to_bytes_type(&self, buf: &mut Vec<u8>) -> usize {
        let bytes = match self {
            Self::A(_) => 1u16.to_be_bytes(),
            Self::NS => 2u16.to_be_bytes(),
            Self::MD => 3u16.to_be_bytes(),
            Self::MF => 4u16.to_be_bytes(),
            Self::CNAME(_) => 5u16.to_be_bytes(),
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
            Self::Raw(i, _) => i.to_be_bytes(),
        };
        buf.push(bytes[0]);
        buf.push(bytes[1]);
        2
    }

    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        trace!("Writing {}", self);

        match self {
            RData::Raw(_, v) => {
                buf.extend(v);
                Ok(v.len())
            }
            RData::A(v4) => {
                buf.extend_from_slice(&v4.octets());
                Ok(4)
            }
            RData::CNAME(s) => encode_str(s, buf),
            _ => todo!(),
        }
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        match self {
            RData::Raw(id, v) => write!(f, "Raw({} => {:?})", id, v),
            RData::A(v4) => write!(f, "A({})", v4),
            RData::CNAME(s) => write!(f, "CNAME({})", s),
            _ => todo!(),
        }
    }
}
