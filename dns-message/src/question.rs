use crate::{encode_str, Result};
use std::default::Default;
use std::fmt;

use tracing::{instrument, trace};
#[derive(Debug, PartialEq)]
/// The question section is used to carry the "question" in most queries, i.e.,
/// the parameters that define what is being asked.
pub struct Question {
    /// RFC1035 - a domain name represented as a sequence of labels, where each
    /// label consists of a length octet followed by that number of octets.  The
    /// domain name terminates with the zero length octet for the null label of
    /// the root.  Note that this field may be an odd number of octets; no
    /// padding is used.
    pub q_name: String,

    /// RFC1035 - a two octet code which specifies the type of the query. The
    /// values for this field include all codes valid for a ['Type'] field,
    /// together with some more general codes which can match more than one type
    /// of RR.
    pub q_type: Type,

    /// RFC1035 - a two octet code that specifies the ['Class`] of the query.
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
/// Types used in [`Question`]s.
pub enum Type {
    /// RFC1035 - (1) a host address.
    A,

    /// RFC1035 - (2) an authoritative name server.
    NS,

    /// RFC1035 - (3) a mail destination (Obsolete - use MX).
    MD,

    /// RFC1035 - (4) a mail forwarder (Obsolete - use MX).
    MF,

    /// RFC1035 - (5) the canonical name for an alias.
    CNAME,

    /// RFC1035 - (6) marks the start of a zone of authority.
    SOA,

    /// RFC1035 - (7) a mailbox domain name (EXPERIMENTAL).
    MB,

    /// RFC1035 - (8) a mail group member (EXPERIMENTAL).
    MG,

    /// RFC1035 - (9) a mail rename domain name (EXPERIMENTAL).
    MR,

    /// RFC1035 - (10) a null RR (EXPERIMENTAL).
    NULL,

    /// RFC1035 - (11) a well known service description.
    WKS,

    /// RFC1035 - (12) a domain name pointer.
    PTR,

    /// RFC1035 - (13) host information.
    HINFO,

    /// RFC1035 - (14) mailbox or mail list information.
    MINFO,

    /// RFC1035 - (15) mail exchange.
    MX,

    /// RFC1035 - (16) text strings.
    TXT,

    /// RFC3596 - The AAAA resource record type is a record specific to the
    /// Internet class that stores a single IPv6 address.
    AAAA,

    /// RFC1035 - (252) A request for a transfer of an entire zone.
    AXFR,

    /// RFC1035 - (253) A request for mailbox-related records (MB, MG or MR).
    MAILB,

    /// RFC1035 - (254) A request for mail agent RRs (Obsolete - see MX).
    MAILA,

    /// RFC1035 - (255) A request for all records.
    STAR,

    /// An unknown [`Type`] - the value is contained within.
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
            Self::AAAA => 28u16.to_be_bytes(),
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
            Self::AAAA => "AAAA",
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
            Type::AAAA => 28,
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
            28 => Type::AAAA,
            252 => Type::AXFR,
            253 => Type::MAILB,
            254 => Type::MAILA,
            255 => Type::STAR,
            _ => Type::Unknown(val),
        }
    }
}

#[derive(Debug, PartialEq)]
/// The class of the query - you will want [`Class::IN`] (the default) 99.99% of
/// the time.
pub enum Class {
    /// RFC1035 - 1 the Internet.
    IN,

    /// RFC1035 - 2 the CSNET class (Obsolete - used only for examples in some
    /// obsolete RFCs)
    CS,

    /// RFC1035 - 3 the CHAOS class.
    CH,

    /// RFC1035 - 4 Hesiod [Dyer 87].
    HS,

    /// RFC1035 - 255 any class.
    STAR,

    /// An unknown class - contained within.
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
