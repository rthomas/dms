use crate::message::error::MessageError;
use crate::message::parser;
use std::fmt;
use std::net::Ipv4Addr;
use tracing::{instrument, trace};

type Result<T> = std::result::Result<T, MessageError>;

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub name_servers: Vec<ResourceRecord>,
    pub additional_records: Vec<ResourceRecord>,
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: Flags,
}

#[derive(Debug, PartialEq)]
pub struct Flags {
    pub qr: bool,       // RFC1035 - Query
    pub opcode: OpCode, // RFC1035
    pub aa: bool,       // RFC1035 - Authorative Answer
    pub tc: bool,       // RFC1035 - Truncation
    pub rd: bool,       // RFC1035 - Recursion Desired
    pub ra: bool,       // RFC1035 - Recursion Available
    pub ad: bool,       // RFC4035, RFC6840 - Authentic Data
    pub cd: bool,       // RFC4035, RFC6840 - Checking Disabled
    pub rcode: RCode,   // RFC1035
}

#[derive(Debug, PartialEq)]
pub struct Question {
    pub qname: String,
    pub qtype: Type,
    pub qclass: Class,
}

#[derive(Debug, PartialEq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: Type,
    pub class: Class,
    pub ttl: u32,
    // TODO - Update this to be an enum with the actual decoded data.
    pub rdata: RData,
}

#[derive(Debug, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    CNAME(String),
    Raw(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Reserved,
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

impl Header {
    #[instrument(skip(buf))]
    fn to_bytes(&self, message: &Message, buf: &mut Vec<u8>) -> Result<usize> {
        let mut pair = self.id.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);

        let mut byte_count = 2;

        byte_count += self.flags.to_bytes(buf)?;

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

        byte_count += 8;

        trace!("Wrote {} bytes", byte_count);

        Ok(byte_count)
    }
}

impl Flags {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut val = 0u8;
        if self.qr {
            val |= 1 << 7;
        }
        val |= self.opcode.as_u8()?;
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

        trace!("Wrote 2 bytes");

        Ok(2)
    }
}

impl RData {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        trace!("Writing {}", self);

        match self {
            RData::Raw(v) => {
                buf.extend(v);
                Ok(v.len())
            }
            RData::A(v4) => {
                buf.extend_from_slice(&v4.octets());
                Ok(4)
            }
            RData::CNAME(s) => str_to_bytes(s, buf),
            _ => todo!(),
        }
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        match self {
            RData::Raw(v) => write!(f, "Raw({:?})", v),
            RData::A(v4) => write!(f, "A({})", v4),
            RData::CNAME(s) => write!(f, "CNAME({})", s),
            _ => todo!(),
        }
    }
}

impl Question {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut byte_count = str_to_bytes(&self.qname, buf)?;
        byte_count += self.qtype.to_bytes(buf);
        byte_count += self.qclass.to_bytes(buf);

        trace!("Wrote {} bytes", byte_count);

        Ok(byte_count)
    }
}

impl ResourceRecord {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        // TODO here is where we would implement the Message Compression -
        // though we will need to wire through a map of the strings and
        // locations. It is perfectly fine with the spec to not implement this.
        let mut byte_count = str_to_bytes(&self.name, buf)?;
        byte_count += self.rtype.to_bytes(buf);
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
        let rdlength = self.rdata.to_bytes(&mut rdata)?;
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

impl OpCode {
    #[instrument]
    fn as_u8(&self) -> Result<u8> {
        match self {
            OpCode::Query => Ok(0),
            OpCode::IQuery => Ok(1),
            OpCode::Status => Ok(2),
            OpCode::Reserved => Err(MessageError::ReservedOpCode),
        }
    }
}

impl RCode {
    #[instrument]
    fn as_u8(&self) -> u8 {
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

impl Class {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> usize {
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

impl Message {
    /// Reads the u8 buffer and parses the DNS message from it.
    ///
    /// This includes the dereferencing of rfc1035 Message Compression pointers,
    /// and collapsing the names into strings.
    #[instrument(skip(input))]
    pub fn from_bytes<'a>(input: &[u8]) -> Result<Message> {
        let (_, message) = parser::read_message(input)?;

        trace!("Read input as: {}", message);

        Ok(message)
    }

    /// Serializes the Message to bytes into the provided buffer, returning the
    /// number of bytes written to the buffer.
    #[instrument(skip(buf))]
    pub fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut byte_count = self.header.to_bytes(&self, buf)?;
        for q in self.questions.iter() {
            byte_count += q.to_bytes(buf)?;
        }
        for a in self.answers.iter() {
            byte_count += a.to_bytes(buf)?;
        }
        for n in self.name_servers.iter() {
            byte_count += n.to_bytes(buf)?;
        }
        for ar in self.additional_records.iter() {
            byte_count += ar.to_bytes(buf)?;
        }

        if byte_count > 512 {
            // TODO set the TR bit to true.
            // Should we also truncate the buffer?
        }

        trace!("Wrote {} bytes", byte_count);

        Ok(byte_count)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        write!(f, "Message(id:{}) - ", self.header.id)?;
        if self.header.flags.qr {
            write!(f, "Response [")?;
            for (i, a) in self.answers.iter().enumerate() {
                if i != 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{} => {}", a.name, a.rdata)?;
            }
            write!(f, "]")?;
        } else {
            write!(f, "Query [")?;
            for (i, q) in self.questions.iter().enumerate() {
                if i != 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}({})", q.qname, q.qtype)?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

#[instrument(skip(buf))]
fn str_to_bytes(s: &str, buf: &mut Vec<u8>) -> Result<usize> {
    let mut byte_count = 0;
    let name_parts = s.split(".");
    for name in name_parts {
        if name.len() > 63 {
            return Err(MessageError::NameLengthExceeded(
                name.len(),
                name.to_string(),
            ));
        }
        let len = name.len() as u8;
        buf.push(len);
        byte_count += 1;
        for b in name.bytes() {
            buf.push(b);
            byte_count += 1;
        }
    }
    buf.push(0);
    byte_count += 1;
    Ok(byte_count)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    #[test]
    fn test_parse_question() {
        setup();
        let input: &[u8] = &[
            83, 202, // ID
            1, 32, // Flags
            0, 1, // qdcount
            0, 0, // ancount
            0, 0, // nscount
            0, 1, // arcount
            // Q Section
            3, 119, 119, 119, // len: 3 - www
            6, 103, 111, 111, 103, 108, 101, // len: 6 - google
            3, 99, 111, 109, // len: 3 - com
            0,   // name terminator
            0, 1, // qtype
            0, 1, // qclass
            // AR Section
            0, // no name
            0, 41, // type
            16, 0, // class
            0, 0, 0, 0, // ttl
            0, 12, // rdlength
            0, 10, 0, 8, 107, 120, 163, 147, 238, 31, 231, 235, // rdata
        ];

        let message = Message::from_bytes(input).unwrap();

        // Header
        assert_eq!(message.header.id, 21450);
        assert!(!message.header.flags.qr);
        assert_eq!(message.header.flags.opcode, OpCode::Query);
        assert!(!message.header.flags.aa);
        assert!(!message.header.flags.tc);
        assert!(message.header.flags.rd);
        assert!(!message.header.flags.ra);
        assert!(message.header.flags.ad);
        assert!(!message.header.flags.cd);
        assert_eq!(message.header.flags.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 0);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 1);

        // Question
        assert_eq!(message.questions[0].qname, "www.google.com");
        assert_eq!(message.questions[0].qtype, Type::A);
        assert_eq!(message.questions[0].qclass, Class::IN);
        println!("{}", message);
    }

    #[test]
    fn test_parse_answer() {
        setup();
        let input: &[u8] = &[
            0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44,
        ];

        let message = Message::from_bytes(input).unwrap();

        // Header
        assert_eq!(message.header.id, 56130);
        assert!(message.header.flags.qr);
        assert_eq!(message.header.flags.opcode, OpCode::Query);
        assert!(!message.header.flags.aa);
        assert!(!message.header.flags.tc);
        assert!(message.header.flags.rd);
        assert!(message.header.flags.ra);
        assert!(!message.header.flags.ad);
        assert!(!message.header.flags.cd);
        assert_eq!(message.header.flags.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 0);

        // Question
        assert_eq!(message.questions[0].qname, "www.northeastern.edu");
        assert_eq!(message.questions[0].qtype, Type::A);
        assert_eq!(message.questions[0].qclass, Class::IN);

        // Answer
        assert_eq!(message.answers[0].name, "www.northeastern.edu");
        assert_eq!(message.answers[0].rtype, Type::A);
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 600);
        assert_eq!(
            message.answers[0].rdata,
            RData::A(Ipv4Addr::new(155, 33, 17, 68))
        );

        println!("{}", message);
    }

    #[test]
    fn test_deserialize_serialize_deserialize() {
        setup();
        let input: &[u8] = &[
            0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44,
        ];

        let message = Message::from_bytes(input).unwrap();

        let mut buf = Vec::new();
        message.to_bytes(&mut buf).unwrap();
        let message2 = Message::from_bytes(&buf[..]).unwrap();
        assert_eq!(message, message2);
    }

    #[test]
    fn test_deserialize_multi_answer() {
        setup();
        let input = &[
            208, 7, // ID
            129, 128, // flags
            0, 1, // qdcount
            0, 4, // ancount
            0, 0, // nscount
            0, 0, // arcount
            // Question section
            3, 119, 119, 119, // www
            9, 109, 105, 99, 114, 111, 115, 111, 102, 116, // microsoft
            3, 99, 111, 109, // com
            0,   // terminator
            0, 1, // qtype - A
            0, 1, // qclass - IN
            // Answer 1
            192, 12, // Name - Pointer @ 12
            0, 5, // type - CNAME
            0, 1, // class - IN
            0, 0, 5, 224, // ttl - 1504
            0, 35, // rdlength - 35
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45,
            99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0, // rdata
            // Answer 2
            192, 47, // Name - Pointer @ 47
            0, 5, // type - CNAME
            0, 1, // class - IN
            0, 0, 17, 174, // ttl - 4526
            0, 55, // rdlength - 55
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45,
            99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 11, 103, 108, 111,
            98, 97, 108, 114, 101, 100, 105, 114, 6, 97, 107, 97, 100, 110, 115, 192,
            77, // rdata - with pointer to 77 at end
            // Answer 3
            192, 94, // name @ 92
            0, 5, // type - cname
            0, 1, // class IN
            0, 0, 3, 102, // ttl - 870
            0, 25, // rdlength - 25
            6, 101, 49, 51, 54, 55, 56, 4, 100, 115, 112, 98, 10, 97, 107, 97, 109, 97, 105, 101,
            100, 103, 101, 192, 77, // rdata w/ pointer to 77
            // Answer 4
            192, 161, // name @ 161
            0, 1, // type - A
            0, 1, // class - IN
            0, 0, 0, 5, // ttl - 5
            0, 4, // rdlength - 4
            23, 40, 73, 65, // rdata
        ];

        let message = Message::from_bytes(input).unwrap();

        assert_eq!(message.header.id, 53255);
        assert!(message.header.flags.qr);
        assert_eq!(message.header.flags.opcode, OpCode::Query);
        assert!(!message.header.flags.aa);
        assert!(!message.header.flags.tc);
        assert!(message.header.flags.rd);
        assert!(message.header.flags.ra);
        assert!(!message.header.flags.ad);
        assert!(!message.header.flags.cd);
        assert_eq!(message.header.flags.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 4);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 0);

        // Question
        assert_eq!(message.questions[0].qname, "www.microsoft.com");
        assert_eq!(message.questions[0].qtype, Type::A);
        assert_eq!(message.questions[0].qclass, Class::IN);

        // Answer 1
        assert_eq!(message.answers[0].name, "www.microsoft.com");
        assert_eq!(message.answers[0].rtype, Type::CNAME);
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 1504);
        assert_eq!(
            message.answers[0].rdata,
            RData::CNAME(String::from("www.microsoft.com-c-3.edgekey.net"))
        );

        // Answer 2
        assert_eq!(message.answers[1].name, "www.microsoft.com-c-3.edgekey.net");
        assert_eq!(message.answers[1].rtype, Type::CNAME);
        assert_eq!(message.answers[1].class, Class::IN);
        assert_eq!(message.answers[1].ttl, 4526);
        assert_eq!(
            message.answers[1].rdata,
            RData::CNAME(String::from(
                "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
            ))
        );

        // Answer 3
        assert_eq!(
            message.answers[2].name,
            "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
        );
        assert_eq!(message.answers[2].rtype, Type::CNAME);
        assert_eq!(message.answers[2].class, Class::IN);
        assert_eq!(message.answers[2].ttl, 870);
        assert_eq!(
            message.answers[2].rdata,
            RData::CNAME(String::from("e13678.dspb.akamaiedge.net"))
        );

        // Answer 4
        assert_eq!(message.answers[3].name, "e13678.dspb.akamaiedge.net");
        assert_eq!(message.answers[3].rtype, Type::A);
        assert_eq!(message.answers[3].class, Class::IN);
        assert_eq!(message.answers[3].ttl, 5);
        assert_eq!(
            message.answers[3].rdata,
            RData::A(Ipv4Addr::new(23, 40, 73, 65))
        );

        println!("{:?}", message);
    }

    #[test]
    fn test_deserialize_no_compression() {
        let input = &[
            50, 87, 129, 128, 0, 1, 0, 4, 0, 0, 0, 0, // Question
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0,
            1, 0, 1, // Answer
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0,
            5, 0, 1, // cname, in
            0, 0, 6, 97, //ttl
            0, 33, //rdlength
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45,
            99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0, 3, 119, 119,
            119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99, 45, 51, 7,
            101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0, 0, 5, 0, 1, 0, 0, 17, 49, 0,
            56, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109,
            45, 99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 11, 103, 108,
            111, 98, 97, 108, 114, 101, 100, 105, 114, 6, 97, 107, 97, 100, 110, 115, 3, 110, 101,
            116, 0, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111,
            109, 45, 99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 11, 103,
            108, 111, 98, 97, 108, 114, 101, 100, 105, 114, 6, 97, 107, 97, 100, 110, 115, 3, 110,
            101, 116, 0, 0, 5, 0, 1, 0, 0, 2, 224, 0, 26, 6, 101, 49, 51, 54, 55, 56, 4, 100, 115,
            112, 98, 10, 97, 107, 97, 109, 97, 105, 101, 100, 103, 101, 3, 110, 101, 116, 0, 6,
            101, 49, 51, 54, 55, 56, 4, 100, 115, 112, 98, 10, 97, 107, 97, 109, 97, 105, 101, 100,
            103, 101, 3, 110, 101, 116, 0, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 23, 202, 168, 212,
        ];

        let message = Message::from_bytes(input).unwrap();

        println!("{:#?}", message)
    }
}
