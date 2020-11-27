use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    name_servers: Vec<ResourceRecord>,
    additional_records: Vec<ResourceRecord>,
}

#[derive(Debug)]
pub struct Header {
    id: u16,
    flags: Flags,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[derive(Debug)]
pub struct Flags {
    qr: bool,       // RFC1035 - Query
    opcode: OpCode, // RFC1035
    aa: bool,       // RFC1035 - Authorative Answer
    tc: bool,       // RFC1035 - Truncation
    rd: bool,       // RFC1035 - Recursion Desired
    ra: bool,       // RFC1035 - Recursion Available
    ad: bool,       // RFC4035, RFC6840 - Authentic Data
    cd: bool,       // RFC4035, RFC6840 - Checking Disabled
    rcode: RCode,   // RFC1035
}

#[derive(Debug)]
pub struct Question {
    qname: String,
    qtype: Type,
    qclass: Class,
}

#[derive(Debug)]
pub struct ResourceRecord {
    name: String,
    rtype: Type,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug)]
struct InnerQuestion {
    qname: Vec<Name>,
    qtype: Type,
    qclass: Class,
}

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
            Name::Pointer(i) => {
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

#[derive(Debug)]
struct InnerResourceRecord {
    name: Vec<Name>,
    rtype: Type,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

impl From<InnerQuestion> for Question {
    fn from(iq: InnerQuestion) -> Self {
        Question {
            qname: flatten_to_string(&iq.qname),
            qtype: iq.qtype,
            qclass: iq.qclass,
        }
    }
}

impl From<InnerResourceRecord> for ResourceRecord {
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

#[derive(Debug, Clone)]
enum Name {
    Name(String),
    Pointer(u16),
    ResolvedPtr(Vec<Name>),
}

#[derive(Debug)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Reserved,
}

#[derive(Debug)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

#[derive(Debug)]
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

impl From<u16> for Type {
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

#[derive(Debug)]
pub enum Class {
    IN,
    CS,
    CH,
    HS,
    STAR,
    Unknown(u16),
}

impl From<u16> for Class {
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
    pub fn parse<'a>(input: &'a [u8]) -> Result<Message, Box<dyn Error + 'a>> {
        let (_, message) = read_message(input)?;

        Ok(message)
    }
}

fn as_u16(input: &[u8]) -> Result<u16, std::num::ParseIntError> {
    let b = [input[0], input[1]];
    Ok(u16::from_be_bytes(b))
}

fn read_u16(input: &[u8]) -> IResult<&[u8], u16> {
    nom::combinator::map_res(nom::bytes::complete::take(2usize), as_u16)(input)
}

fn as_u32(input: &[u8]) -> Result<u32, std::num::ParseIntError> {
    let b = [input[0], input[1], input[2], input[3]];
    Ok(u32::from_be_bytes(b))
}

fn read_u32(input: &[u8]) -> IResult<&[u8], u32> {
    nom::combinator::map_res(nom::bytes::complete::take(4usize), as_u32)(input)
}

fn as_flags<'a>(input: &'a [u8]) -> Result<Flags, Box<dyn Error + 'a>> {
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
}

fn read_flags(input: &[u8]) -> IResult<&[u8], Flags> {
    map_res(take_bytes(2usize), as_flags)(input)
}

fn as_header<'a>(input: &'a [u8]) -> Result<Header, Box<dyn Error + 'a>> {
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
}

fn read_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_res(take_bytes(12usize), as_header)(input)
}

fn as_name(input: &[u8]) -> Result<Name, Box<dyn Error>> {
    Ok(Name::Name(std::str::from_utf8(input)?.to_string()))
}

fn read_names(input: &[u8]) -> IResult<&[u8], Vec<Name>> {
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
                Ok((i, NameRecord::Offset(offset)))
            } else {
                let mut len: u8 = flags << 6;
                let (i, l): (_, u8) = take_bits(6usize)(i)?;
                len = len | l;
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

                let (i, name) = map_res(take_bytes(length), as_name)(i)?;
                qname.push(name);
                input = i;
            }
        }
    }
    Ok((input, qname))
}

fn read_question(input: &[u8]) -> IResult<&[u8], InnerQuestion> {
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

fn read_resource_record(input: &[u8]) -> IResult<&[u8], InnerResourceRecord> {
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

impl fmt::Display for InvalidMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "InvalidMessageError: {}", self.message)?;
        Ok(())
    }
}

impl Error for InvalidMessageError {}

/// This just does a single level of pointer resolution TODO - we should
/// dereference all of the pointers, rather than a single level - and need
/// to add loop protection even for the case of a single pointer pointing back to itself.
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

fn read_message(input: &[u8]) -> IResult<&[u8], Message> {
    // TODO - There has to be a better way to consume all of the input than this...
    map_res(take_bytes(input.len()), as_message)(input)
}
