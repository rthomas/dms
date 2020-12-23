use crate::{encode_str, Class, Result};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{instrument, trace};

#[derive(Debug, PartialEq)]
/// The answer, authority and additional sections all share the same format,
/// that is a variable number of [`ResourceRecord`]s.
///
/// These can be constructed with a [`crate::ResourceRecordBuilder`].
pub struct ResourceRecord {
    /// A domain name to which this resource record pertains.
    pub name: String,

    /// The type and data of the resource record.
    pub data: RData,

    /// The class of the data in the `data` field.
    pub class: Class,

    /// RFC1035 - a 32 bit unsigned integer that specifies the time interval (in
    /// seconds) that the resource record may be cached before it should be
    /// discarded.  Zero values are interpreted to mean that the RR can only be
    /// used for the transaction in progress, and should not be cached.
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
/// The [`ResourceRecord`] data.
pub enum RData {
    /// RFC1035 - (1) a host address.
    A(Ipv4Addr),

    /// RFC1035 - (2) an authoritative name server.
    NS,

    /// RFC1035 - (3) a mail destination (Obsolete - use MX).
    MD,

    /// RFC1035 - (4) a mail forwarder (Obsolete - use MX).
    MF,

    /// RFC1035 - (5) the canonical name for an alias.
    CNAME(String),

    /// RFC1035 - (6) marks the start of a zone of authority.
    ///
    /// The components consist of:
    /// - MNAME - The <domain-name> of the name server that was the original or
    ///   primary source of data for this zone.
    /// - RNAME - A <domain-name> which specifies the mailbox of the person
    ///   responsible for this zone.
    /// - SERIAL - The unsigned 32 bit version number of the original copy of
    ///   the zone. Zone transfers preserve this value. This value wraps and
    ///   should be compared using sequence space arithmetic.
    /// - REFRESH - A 32 bit time interval before the zone should be refreshed.
    /// - RETRY - A 32 bit time interval that should elapse before a failed
    ///   refresh should be retried.
    /// - EXPIRE - A 32 bit time value that specifies the upper limit on the
    ///   time interval that can elapse before the zone is no longer
    ///   authoritative.
    /// - MINIMUM - The unsigned 32 bit minimum TTL field that should be
    ///   exported with any RR from this zone.
    SOA(String, String, u32, u32, u32, u32, u32),

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
    TXT(String),

    /// RFC3596 - The AAAA resource record type is a record specific to the
    /// Internet class that stores a single IPv6 address.
    AAAA(Ipv6Addr),

    /// Raw rdata - when an unknown type is encountered, they type and bytes will be in a Raw.
    /// The u16 is the rfc1035 type and the Vec<u8> is the bytes.
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
            RData::SOA(_, _, _, _, _, _, _) => 6,
            RData::MB => 7,
            RData::MG => 8,
            RData::MR => 9,
            RData::NULL => 10,
            RData::WKS => 11,
            RData::PTR => 12,
            RData::HINFO => 13,
            RData::MINFO => 14,
            RData::MX => 15,
            RData::TXT(_) => 16,
            RData::AAAA(_) => 28,
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
            RData::SOA(mname, rname, serial, refresh, retry, expire, minimum) => {
                let mut bytes_written = encode_str(mname, buf)?;
                bytes_written += encode_str(rname, buf)?;

                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
                buf.extend_from_slice(&minimum.to_be_bytes());
                bytes_written += 20;

                Ok(bytes_written)
            }
            RData::TXT(s) => {
                buf.extend_from_slice(s.as_bytes());
                Ok(s.len())
            }
            RData::AAAA(v6) => {
                buf.extend_from_slice(&v6.octets());
                Ok(16)
            }
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
            Self::SOA(mname, rname, serial, refresh, retry, expire, minimum) => write!(
                f,
                "SOA({}, {}, {}, {}, {}, {}, {})",
                mname, rname, serial, refresh, retry, expire, minimum
            ),
            Self::MB => write!(f, "MB"),
            Self::MG => write!(f, "MG"),
            Self::MR => write!(f, "MR"),
            Self::NULL => write!(f, "NULL"),
            Self::WKS => write!(f, "WKS"),
            Self::PTR => write!(f, "PTR"),
            Self::HINFO => write!(f, "HINFO"),
            Self::MINFO => write!(f, "MINFO"),
            Self::MX => write!(f, "MX"),
            Self::TXT(s) => write!(f, "TXT({})", s),
            Self::AAAA(v6) => write!(f, "AAAA({})", v6),
            Self::Raw(id, v) => write!(f, "Raw({}: {:?})", id, v),
        }
    }
}
