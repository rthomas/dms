use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::error::Error;

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
    qnames: Vec<QName>,
    qtype: QType,
    qclass: Class,
}

#[derive(Debug)]
pub struct ResourceRecord {
    name: Vec<QName>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
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
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Unknown,
}

#[derive(Debug)]
pub enum QType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    STAR = 255,
    Unknown,
}

#[derive(Debug)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    STAR = 255,
    Unknown,
}

impl Message {
    pub fn parse<'a>(input: &'a [u8]) -> Result<Message, Box<dyn Error + 'a>> {
        let (_, message) = read_message(input)?;

        // TODO - we now need to resolve all of the QName::Pointer records

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
                (i, _) => (i, RCode::Unknown),
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

fn as_qname(input: &[u8]) -> Result<QName, Box<dyn Error>> {
    Ok(QName::Name(std::str::from_utf8(input)?.to_string()))
}

#[derive(Debug)]
enum QName {
    Name(String),
    Pointer(u16),
}

fn read_qnames(input: &[u8]) -> IResult<&[u8], Vec<QName>> {
    use nom::bits::bits;

    let mut qnames = Vec::new();
    let mut input = input;

    /// Helper for pulling out either the length of a QName segment, or the
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
                qnames.push(QName::Pointer(offset));
                input = i;
                break;
            }
            NameRecord::Length(length) => {
                // Names are termintated with a NULL byte.
                if length == 0 {
                    input = i;
                    break;
                }

                let (i, qname) = map_res(take_bytes(length), as_qname)(i)?;
                qnames.push(qname);
                input = i;
            }
        }
    }
    Ok((input, qnames))
}

fn read_question(input: &[u8]) -> IResult<&[u8], Question> {
    let (input, qnames) = read_qnames(input)?;

    let (input, qtype) = match read_u16(input)? {
        (i, 1) => (i, QType::A),
        (i, 2) => (i, QType::NS),
        (i, 3) => (i, QType::MD),
        (i, 4) => (i, QType::MF),
        (i, 5) => (i, QType::CNAME),
        (i, 6) => (i, QType::SOA),
        (i, 7) => (i, QType::MB),
        (i, 8) => (i, QType::MG),
        (i, 9) => (i, QType::MR),
        (i, 10) => (i, QType::NULL),
        (i, 11) => (i, QType::WKS),
        (i, 12) => (i, QType::PTR),
        (i, 13) => (i, QType::HINFO),
        (i, 14) => (i, QType::MINFO),
        (i, 15) => (i, QType::MX),
        (i, 16) => (i, QType::TXT),
        (i, 252) => (i, QType::AXFR),
        (i, 253) => (i, QType::MAILB),
        (i, 254) => (i, QType::MAILA),
        (i, 255) => (i, QType::STAR),
        (i, _) => (i, QType::Unknown),
    };
    let (input, qclass) = match read_u16(input)? {
        (i, 1) => (i, Class::IN),
        (i, 2) => (i, Class::CS),
        (i, 3) => (i, Class::CH),
        (i, 4) => (i, Class::HS),
        (i, 255) => (i, Class::STAR),
        (i, _) => (i, Class::Unknown),
    };

    let question = Question {
        qnames,
        qtype,
        qclass,
    };
    Ok((input, question))
}

fn read_resource_record(input: &[u8]) -> IResult<&[u8], ResourceRecord> {
    let (input, name) = read_qnames(input)?;
    let (input, rtype) = read_u16(input)?;
    let (input, class) = read_u16(input)?;
    let (input, ttl) = read_u32(input)?;
    let (input, rdlength) = read_u16(input)?;
    let (_, rdata) = take_bytes(rdlength)(input)?;
    let rdata = Vec::from(rdata);
    Ok((
        input,
        ResourceRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        },
    ))
}

fn as_message<'a>(input: &'a [u8]) -> Result<Message, Box<dyn Error + 'a>> {
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

    Ok(Message {
        header,
        questions,
        answers,
        name_servers,
        additional_records,
    })
}

fn read_message(input: &[u8]) -> IResult<&[u8], Message> {
    // TODO - There has to be a better way to consume all of the input than this...
    map_res(take_bytes(input.len()), as_message)(input)
}
