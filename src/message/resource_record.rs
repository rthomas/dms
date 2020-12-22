use crate::message::{encode_str, Class, Result};
use std::fmt;
use std::net::Ipv4Addr;
use tracing::{instrument, trace};

#[derive(Debug, PartialEq)]
pub struct ResourceRecord {
    pub name: String,
    pub data: RData,
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

        let r_type = self.data.as_u16().to_be_bytes();
        buf.push(r_type[0]);
        buf.push(r_type[1]);
        byte_count += 2;

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
        let rdlength = self.data.to_bytes(&mut rdata)?;
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
    /// Raw rdata - u16 is the rfc1035 type and the Vec<u8> is the bytes.
    /// TODO: This will only be needed for fallback once all of the types above are implemented.
    Raw(u16, Vec<u8>),
}

impl RData {
    fn as_u16(&self) -> u16 {
        match self {
            RData::A(_) => 1,
            RData::NS => 2,
            RData::MD => 3,
            RData::MF => 4,
            RData::CNAME(_) => 5,
            RData::SOA => 6,
            RData::MB => 7,
            RData::MG => 8,
            RData::MR => 9,
            RData::NULL => 10,
            RData::WKS => 11,
            RData::PTR => 12,
            RData::HINFO => 13,
            RData::MINFO => 14,
            RData::MX => 15,
            RData::TXT => 16,
            RData::AXFR => 252,
            RData::MAILB => 253,
            RData::MAILA => 254,
            RData::STAR => 255,
            RData::Raw(i, _) => *i,
        }
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
            Self::A(v4) => write!(f, "A({})", v4),
            Self::NS => write!(f, "NS"),
            Self::MD => write!(f, "MD"),
            Self::MF => write!(f, "MF"),
            Self::CNAME(s) => write!(f, "CNAME({})", s),
            Self::SOA => write!(f, "SOA"),
            Self::MB => write!(f, "MB"),
            Self::MG => write!(f, "MG"),
            Self::MR => write!(f, "MR"),
            Self::NULL => write!(f, "NULL"),
            Self::WKS => write!(f, "WKS"),
            Self::PTR => write!(f, "PTR"),
            Self::HINFO => write!(f, "HINFO"),
            Self::MINFO => write!(f, "MINFO"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AXFR => write!(f, "AXFR"),
            Self::MAILB => write!(f, "MAILB"),
            Self::MAILA => write!(f, "MAILA"),
            Self::STAR => write!(f, "*"),
            Self::Raw(id, v) => write!(f, "Raw({}: {:?})", id, v),
        }
    }
}
