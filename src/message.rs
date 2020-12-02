use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::error::Error;
use std::fmt;
use tracing::{instrument, trace};

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
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
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
    pub rdata: Vec<u8>,
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

#[derive(Debug)]
struct InnerQuestion {
    qname: Vec<Name>,
    qtype: Type,
    qclass: Class,
}

#[derive(Debug)]
struct InnerResourceRecord {
    name: Vec<Name>,
    rtype: Type,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
enum Name {
    Name(String),
    Pointer(u16),
    ResolvedPtr(Vec<Name>),
}

impl Header {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
        let mut pair = self.id.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);

        self.flags.to_bytes(buf)?;

        pair = self.qd_count.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = self.an_count.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = self.ns_count.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);
        pair = self.ar_count.to_be_bytes();
        buf.push(pair[0]);
        buf.push(pair[1]);

        Ok(())
    }
}

impl Flags {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
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
        Ok(())
    }
}

impl Question {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
        str_to_bytes(&self.qname, buf)?;
        self.qtype.to_bytes(buf);
        self.qclass.to_bytes(buf);

        Ok(())
    }
}

impl ResourceRecord {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
        // TODO here is where we would implement the Message Compression -
        // though we will need to wire through a map of the strings and
        // locations. It is perfectly fine with the spec to not implement this.
        str_to_bytes(&self.name, buf)?;
        self.rtype.to_bytes(buf);
        self.class.to_bytes(buf);
        let ttl = self.ttl.to_be_bytes();
        buf.push(ttl[0]);
        buf.push(ttl[1]);
        buf.push(ttl[2]);
        buf.push(ttl[3]);

        let rdlength = (self.rdata.len() as u16).to_be_bytes();
        buf.push(rdlength[0]);
        buf.push(rdlength[1]);

        buf.extend_from_slice(&self.rdata[..]);
        Ok(())
    }
}

impl From<InnerQuestion> for Question {
    #[instrument]
    fn from(iq: InnerQuestion) -> Self {
        Question {
            qname: flatten_to_string(&iq.qname),
            qtype: iq.qtype,
            qclass: iq.qclass,
        }
    }
}

impl From<InnerResourceRecord> for ResourceRecord {
    #[instrument]
    fn from(irr: InnerResourceRecord) -> Self {
        ResourceRecord {
            name: flatten_to_string(&irr.name),
            rtype: irr.rtype,
            class: irr.class,
            ttl: irr.ttl,
            rdata: irr.rdata,
        }
    }
}

impl OpCode {
    #[instrument]
    fn as_u8(&self) -> Result<u8, InvalidMessageError> {
        match self {
            OpCode::Query => Ok(0),
            OpCode::IQuery => Ok(1),
            OpCode::Status => Ok(2),
            OpCode::Reserved => Err(InvalidMessageError::new(
                "Use of Reserved OpCode".to_string(),
            )),
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
    fn to_bytes(&self, buf: &mut Vec<u8>) {
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

impl Class {
    #[instrument(skip(buf))]
    fn to_bytes(&self, buf: &mut Vec<u8>) {
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
    pub fn from_bytes<'a>(input: &'a [u8]) -> Result<Message, Box<dyn Error + 'a>> {
        let (_, message) = read_message(input)?;

        Ok(message)
    }

    /// Serializes the Message to bytes into the provided buffer.
    #[instrument(skip(buf))]
    pub fn to_bytes(&self, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
        self.header.to_bytes(buf)?;
        for q in self.questions.iter() {
            q.to_bytes(buf)?;
        }
        for a in self.answers.iter() {
            a.to_bytes(buf)?;
        }
        for n in self.name_servers.iter() {
            n.to_bytes(buf)?;
        }
        for ar in self.additional_records.iter() {
            ar.to_bytes(buf)?;
        }

        Ok(())
    }
}

#[instrument(skip(input))]
fn read_u16(input: &[u8]) -> IResult<&[u8], u16> {
    trace!("reading u16");
    nom::combinator::map(nom::bytes::complete::take(2usize), |input: &[u8]| {
        let b = [input[0], input[1]];
        u16::from_be_bytes(b)
    })(input)
}

#[instrument(skip(input))]
fn read_u32(input: &[u8]) -> IResult<&[u8], u32> {
    trace!("reading u32");
    nom::combinator::map(nom::bytes::complete::take(4usize), |input: &[u8]| {
        let b = [input[0], input[1], input[2], input[3]];
        u32::from_be_bytes(b)
    })(input)
}

#[instrument(skip(input))]
fn read_flags(input: &[u8]) -> IResult<&[u8], Flags> {
    map_res(
        take_bytes(2usize),
        |input| -> Result<Flags, Box<dyn Error>> {
            trace!("reading flags");
            use nom::bits::bits;
            use nom::bits::complete::tag as tag_bits;

            use nom::combinator::map;

            let (_, (qr, opcode, aa, tc, rd, ra, ad, cd, rcode)) =
                bits::<_, _, nom::error::Error<_>, nom::error::Error<_>, _>(|i| {
                    let is_one = |s: u8| s == 1;
                    let (i, qr) = map(take_bits(1usize), is_one)(i)?;
                    let (i, opcode) = match map(take_bits(4usize), |s: u8| s)(i)? {
                        (i, 0) => (i, OpCode::Query),
                        (i, 1) => (i, OpCode::IQuery),
                        (i, 2) => (i, OpCode::Status),
                        (i, _) => (i, OpCode::Reserved),
                    };
                    let (i, aa) = map(take_bits(1usize), is_one)(i)?;
                    let (i, tc) = map(take_bits(1usize), is_one)(i)?;
                    let (i, rd) = map(take_bits(1usize), is_one)(i)?;
                    let (i, ra) = map(take_bits(1usize), is_one)(i)?;
                    let (i, _) = tag_bits(0, 1usize)(i)?;
                    let (i, ad) = map(take_bits(1usize), is_one)(i)?;
                    let (i, cd) = map(take_bits(1usize), is_one)(i)?;
                    let (i, rcode) = match map(take_bits(4usize), |s: u8| s)(i)? {
                        (i, 0) => (i, RCode::NoError),
                        (i, 1) => (i, RCode::FormatError),
                        (i, 2) => (i, RCode::ServerFailure),
                        (i, 3) => (i, RCode::NameError),
                        (i, 4) => (i, RCode::NotImplemented),
                        (i, 5) => (i, RCode::Refused),
                        (i, x) => (i, RCode::Unknown(x)),
                    };
                    Ok(((i), (qr, opcode, aa, tc, rd, ra, ad, cd, rcode)))
                })(input)?;

            Ok(Flags {
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                ad,
                cd,
                rcode,
            })
        },
    )(input)
}

#[instrument(skip(input))]
fn read_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_res(
        take_bytes(12usize),
        |input| -> Result<Header, Box<dyn Error>> {
            trace!("reading header");
            let (input, id) = read_u16(input)?;
            let (input, flags) = read_flags(input)?;
            let (input, qd_count) = read_u16(input)?;
            let (input, an_count) = read_u16(input)?;
            let (input, ns_count) = read_u16(input)?;
            let (_, ar_count) = read_u16(input)?;

            Ok(Header {
                id,
                flags,
                qd_count,
                an_count,
                ns_count,
                ar_count,
            })
        },
    )(input)
}

#[instrument(skip(input))]
fn read_names(input: &[u8]) -> IResult<&[u8], Vec<Name>> {
    trace!("reading names");
    use nom::bits::bits;

    let mut qname = Vec::new();
    let mut input = input;

    /// Helper for pulling out either the length of a Name segment, or the
    /// offset of the name to parse.
    enum NameRecord {
        Offset(u16),
        Length(u8),
    }

    loop {
        // Read the length, or the offset if using compression.
        let (i, name_record) = bits::<_, _, nom::error::Error<_>, nom::error::Error<_>, _>(|i| {
            let (i, flags): (_, u8) = take_bits(2usize)(i)?;
            if flags == 0b11 {
                // This is a compressed offset
                let (i, offset): (_, u16) = take_bits(14usize)(i)?;
                trace!("Name pointer at offset: {}", offset);
                Ok((i, NameRecord::Offset(offset)))
            } else {
                let mut len: u8 = flags << 6;
                let (i, l): (_, u8) = take_bits(6usize)(i)?;
                len = len | l;
                trace!("Name of length {} found", len);
                Ok((i, NameRecord::Length(len)))
            }
        })(input)?;

        match name_record {
            NameRecord::Offset(offset) => {
                qname.push(Name::Pointer(offset));
                input = i;
                break;
            }
            NameRecord::Length(length) => {
                // Names are termintated with a NULL byte.
                if length == 0 {
                    input = i;
                    break;
                }

                let (i, name) = map_res(take_bytes(length), |i| -> Result<Name, Box<dyn Error>> {
                    Ok(Name::Name(std::str::from_utf8(i)?.to_string()))
                })(i)?;
                qname.push(name);
                input = i;
            }
        }
    }
    Ok((input, qname))
}

#[instrument(skip(input))]
fn read_question(input: &[u8]) -> IResult<&[u8], InnerQuestion> {
    trace!("reading question");
    let (input, qname) = read_names(input)?;

    let (input, qtype) = {
        let (i, q) = read_u16(input)?;
        (i, Type::from(q))
    };
    let (input, qclass) = {
        let (i, c) = read_u16(input)?;
        (i, Class::from(c))
    };

    Ok((
        input,
        InnerQuestion {
            qname,
            qtype,
            qclass,
        },
    ))
}

#[instrument(skip(input))]
fn read_resource_record(input: &[u8]) -> IResult<&[u8], InnerResourceRecord> {
    trace!("reading resource record");
    let (input, name) = read_names(input)?;
    let (input, rtype) = {
        let (i, r) = read_u16(input)?;
        (i, Type::from(r))
    };
    let (input, class) = {
        let (i, c) = read_u16(input)?;
        (i, Class::from(c))
    };
    let (input, ttl) = read_u32(input)?;
    let (input, rdlength) = read_u16(input)?;

    trace!("Found rdata of length: {}", rdlength);

    let (_, rdata) = take_bytes(rdlength)(input)?;
    let rdata = Vec::from(rdata);
    Ok((
        input,
        InnerResourceRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        },
    ))
}

#[instrument(skip(input))]
fn read_message(input: &[u8]) -> IResult<&[u8], Message> {
    trace!("reading message");
    // TODO - There has to be a better way to consume all of the input than this...
    map_res(take_bytes(input.len()), as_message)(input)
}

#[instrument(skip(input))]
fn as_message<'a>(input: &'a [u8]) -> Result<Message, Box<dyn Error + 'a>> {
    let original_input = input;
    let (mut input, header) = read_header(input)?;

    let mut questions = Vec::new();
    for _ in 0..header.qd_count {
        let (i, question) = read_question(input)?;
        input = i;
        questions.push(question);
    }

    let mut answers = Vec::new();
    for _ in 0..header.an_count {
        let (i, record) = read_resource_record(input)?;
        input = i;
        answers.push(record);
    }

    let mut name_servers = Vec::new();
    for _ in 0..header.ns_count {
        let (i, record) = read_resource_record(input)?;
        input = i;
        name_servers.push(record);
    }

    let mut additional_records = Vec::new();
    for _ in 0..header.ar_count {
        let (i, record) = read_resource_record(input)?;
        input = i;
        additional_records.push(record);
    }

    trace!("resolving name pointers");

    // Resolve the Name::Pointer records.
    for q in questions.iter_mut() {
        resolve_names(original_input, &mut q.qname)?;
    }
    for a in answers.iter_mut() {
        resolve_names(original_input, &mut a.name)?;
    }
    for a in name_servers.iter_mut() {
        resolve_names(original_input, &mut a.name)?;
    }
    for a in additional_records.iter_mut() {
        resolve_names(original_input, &mut a.name)?;
    }

    Ok(Message {
        header,
        questions: questions.drain(..).map(Question::from).collect(),
        answers: answers.drain(..).map(ResourceRecord::from).collect(),
        name_servers: name_servers.drain(..).map(ResourceRecord::from).collect(),
        additional_records: additional_records
            .drain(..)
            .map(ResourceRecord::from)
            .collect(),
    })
}

#[derive(Debug)]
pub struct InvalidMessageError {
    message: String,
}

impl InvalidMessageError {
    fn new(message: String) -> Self {
        InvalidMessageError { message }
    }
}

impl fmt::Display for InvalidMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "InvalidMessageError: {}", self.message)?;
        Ok(())
    }
}

impl Error for InvalidMessageError {}

#[instrument(skip(buf))]
fn str_to_bytes(s: &str, buf: &mut Vec<u8>) -> Result<(), InvalidMessageError> {
    let name_parts = s.split(".");
    for name in name_parts {
        if name.len() > 63 {
            return Err(InvalidMessageError::new(format!(
                "The name part {:?} exceeds the limit of 63 bytes.",
                name
            )));
        }
        let len = name.len() as u8;
        buf.push(len);
        for b in name.bytes() {
            buf.push(b);
        }
    }
    buf.push(0);
    Ok(())
}

/// Splits the string by the '.' character and appends each section preceeded by
/// its length. This function will append the NULL terminating byte.
#[instrument]
fn flatten_to_string(names: &Vec<Name>) -> String {
    let mut name = String::new();
    for n in names.iter() {
        match n {
            Name::Name(part) => {
                name.push_str(part);
                name.push('.');
            }
            Name::ResolvedPtr(names) => {
                let s = flatten_to_string(names);
                name.push_str(&s);
            }
            Name::Pointer(_i) => {
                // TODO - Fix this so that we resolve all pointers.
                eprintln!("WARNING - FOUND UNRESOLVED POINTER....SKIPPING");
            }
        }
    }
    // Remove the trailing '.'
    if name.chars().last() == Some('.') {
        name.pop();
    }
    name
}

/// This just does a single level of pointer resolution TODO - we should
/// dereference all of the pointers, rather than a single level.
#[instrument(skip(input))]
fn resolve_names<'a>(input: &'a [u8], names: &mut Vec<Name>) -> Result<(), Box<dyn Error + 'a>> {
    use std::collections::HashSet;

    let mut seen_ptrs = HashSet::new();

    for n in names.iter_mut() {
        match n {
            Name::Pointer(ptr) => {
                if seen_ptrs.contains(ptr) {
                    return Err(Box::new(InvalidMessageError {
                        message: format!(
                            "Circular reference - detected a pointer we have seen already: {}",
                            *ptr
                        )
                        .to_string(),
                    }));
                }
                seen_ptrs.insert(*ptr);
                let (_, names) = read_names(&input[*ptr as usize..input.len()])?;
                *n = Name::ResolvedPtr(names);
            }
            _ => {}
        }
    }
    Ok(())
}
