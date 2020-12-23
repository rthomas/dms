use crate::{Message, MessageError, Result};
use std::default::Default;
use tracing::{instrument, trace};

#[derive(Debug, PartialEq)]
/// The DNS Message Header as per RFC1035 and RFC2535.
pub struct Header {
    /// RFC1035 - A 16 bit identifier assigned by the program that generates any
    /// kind of query. This identifier is copied the corresponding reply and
    /// can be used by the requester to match up replies to outstanding queries.
    pub id: u16,

    /// RFC1035 - A one bit field that specifies whether this message is a query
    /// (0), or a response (1).
    pub qr: bool,

    /// RFC1035 -  A four bit field that specifies kind of query in this
    /// message.  This value is set by the originator of a query and copied into
    /// the response.
    pub opcode: OpCode,

    /// RFC1035 - Authoritative Answer - this bit is valid in responses, and
    /// specifies that the responding name server is an authority for the domain
    /// name in question section.
    pub aa: bool,

    /// RFC1035 - TrunCation - specifies that this message was truncated due to
    /// length greater than that permitted on the transmission channel.
    pub tc: bool,

    /// RFC1035 - Recursion Desired - this bit may be set in a query and is
    /// copied into the response. If RD is set, it directs the name server to
    /// pursue the query recursively.
    pub rd: bool,

    /// RFC1035 - Recursion Available - this be is set or cleared in a response,
    /// and denotes whether recursive query support is available in the name
    /// server.
    pub ra: bool,

    /// RFC2535 - The AD (authentic data) bit indicates in a response that all
    /// the data included in the answer and authority portion of the response
    /// has been authenticated by the server according to the policies of that
    /// server.
    pub ad: bool,

    /// RFC2535 - The CD (checking disabled) bit indicates in a query that
    /// Pending (non-authenticated) data is acceptable to the resolver sending
    /// the query.
    pub cd: bool,

    /// RFC1035 - Response code - this 4 bit field is set as part of responses.
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
/// A four bit field that specifies kind of query in this message.  This value
/// is set by the originator of a query and copied into the response.
pub enum OpCode {
    /// A standard query.
    Query,

    /// An inverse query.
    IQuery,

    /// A server status request.
    Status,

    /// An unknown OpCode (contained within).
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
/// Response code - this 4 bit field is set as part of responses.
pub enum RCode {
    /// No error condition.
    NoError,

    /// Format error - The name server was unable to interpret the query.
    FormatError,

    /// Server failure - The name server was unable to process this query due to
    /// a problem with the name server.
    ServerFailure,

    /// Name Error - Meaningful only for responses from an authoritative name
    /// server, this code signifies that the domain name referenced in the query
    /// does not exist.
    NameError,

    /// Not Implemented - The name server does not support the requested kind of
    /// query.
    NotImplemented,

    /// Refused - The name server refuses to perform the specified operation for
    /// policy reasons.  For example, a name server may not wish to provide the
    /// information to the particular requester, or a name server may not wish
    /// to perform a particular operation (e.g., zone transfer) for particular
    /// data.
    Refused,

    /// The response code was unknown (contained within).
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
