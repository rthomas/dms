use crate::error::MessageError;
use crate::{Class, Header, Message, OpCode, Question, RCode, RData, ResourceRecord, Result, Type};
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{error, instrument, trace};

#[derive(Debug)]
struct RawHeader {
    header: Header,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[derive(Debug)]
struct RawQuestion {
    qname: Vec<Name>,
    qtype: Type,
    qclass: Class,
}

#[derive(Debug)]
struct RawResourceRecord {
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

impl From<RawHeader> for Header {
    fn from(ih: RawHeader) -> Self {
        ih.header
    }
}

impl From<RawQuestion> for Question {
    #[instrument]
    fn from(iq: RawQuestion) -> Self {
        Question {
            q_name: flatten_to_string(&iq.qname),
            q_type: iq.qtype,
            q_class: iq.qclass,
        }
    }
}

/// We can't implement the From trait here as we need a reference to the
/// original input in order to dereference the name pointers.
#[instrument(skip(input))]
fn from_irr(input: &[u8], irr: RawResourceRecord) -> Result<ResourceRecord> {
    let rdata = match irr.rtype {
        Type::A => RData::A(Ipv4Addr::new(
            irr.rdata[0],
            irr.rdata[1],
            irr.rdata[2],
            irr.rdata[3],
        )),
        Type::CNAME => {
            let (_, mut names) = read_names(&irr.rdata)?;
            resolve_names(input, &mut names, &mut HashSet::new())?;
            let name = flatten_to_string(&names);
            RData::CNAME(name)
        }
        Type::SOA => {
            let (i, mut mnames) = read_names(&irr.rdata)?;
            resolve_names(input, &mut mnames, &mut HashSet::new())?;
            let mname = flatten_to_string(&mnames);

            let (i, mut rnames) = read_names(i)?;
            resolve_names(input, &mut rnames, &mut HashSet::new())?;
            let rname = flatten_to_string(&rnames);

            let (i, serial) = read_u32(i)?;
            let (i, refresh) = read_u32(i)?;
            let (i, retry) = read_u32(i)?;
            let (i, expire) = read_u32(i)?;
            let (_, minimum) = read_u32(i)?;

            RData::SOA(mname, rname, serial, refresh, retry, expire, minimum)
        }
        Type::TXT => RData::TXT(String::from_utf8(irr.rdata)?),
        Type::AAAA => {
            let mut v6: [u8; 16] = [0; 16];
            v6.copy_from_slice(&input[0..16]);
            RData::AAAA(Ipv6Addr::from(v6))
        }
        _ => RData::Raw(irr.rtype.into(), irr.rdata),
    };

    trace!("Parsed rdata as {}", rdata);

    Ok(ResourceRecord {
        name: flatten_to_string(&irr.name),
        data: rdata,
        class: irr.class,
        ttl: irr.ttl,
    })
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
fn read_header(input: &[u8]) -> IResult<&[u8], RawHeader> {
    use nom::bits::bits;
    use nom::bits::complete::tag as tag_bits;
    use nom::combinator::map;

    map_res(take_bytes(12usize), |input| -> Result<RawHeader> {
        trace!("reading header");
        let (input, id) = read_u16(input)?;

        trace!("reading flags");
        let (input, (qr, opcode, aa, tc, rd, ra, ad, cd, rcode)) =
            bits::<_, _, nom::error::Error<_>, nom::error::Error<_>, _>(|i| {
                let is_one = |s: u8| s == 1;
                let (i, qr) = map(take_bits(1usize), is_one)(i)?;
                let (i, opcode) = map(take_bits(4usize), |s: u8| match s {
                    0 => OpCode::Query,
                    1 => OpCode::IQuery,
                    2 => OpCode::Status,
                    n => OpCode::Unknown(n),
                })(i)?;
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

        let (input, qd_count) = read_u16(input)?;
        let (input, an_count) = read_u16(input)?;
        let (input, ns_count) = read_u16(input)?;
        let (_, ar_count) = read_u16(input)?;

        Ok(RawHeader {
            header: Header {
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                ad,
                cd,
                rcode,
            },
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    })(input)
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

                let (i, name) = map_res(take_bytes(length), |i| -> Result<Name> {
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
fn read_question(input: &[u8]) -> IResult<&[u8], RawQuestion> {
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
        RawQuestion {
            qname,
            qtype,
            qclass,
        },
    ))
}

#[instrument(skip(input))]
fn read_resource_record(input: &[u8]) -> IResult<&[u8], RawResourceRecord> {
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

    let (input, rdata) = take_bytes(rdlength)(input)?;
    trace!("rdata: {:?}", rdata);
    let rdata = Vec::from(rdata);
    Ok((
        input,
        RawResourceRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        },
    ))
}

#[instrument(skip(input))]
pub(crate) fn read_message(input: &[u8]) -> IResult<&[u8], Message> {
    trace!("reading message");
    // TODO - There has to be a better way to consume all of the input than this...
    map_res(take_bytes(input.len()), as_message)(input)
}

#[instrument(skip(input))]
fn as_message<'a>(input: &[u8]) -> Result<Message> {
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
        resolve_names(original_input, &mut q.qname, &mut HashSet::new())?;
    }
    for a in answers.iter_mut() {
        resolve_names(original_input, &mut a.name, &mut HashSet::new())?;
    }
    for a in name_servers.iter_mut() {
        resolve_names(original_input, &mut a.name, &mut HashSet::new())?;
    }
    for a in additional_records.iter_mut() {
        resolve_names(original_input, &mut a.name, &mut HashSet::new())?;
    }

    Ok(Message {
        header: header.into(),
        questions: questions.drain(..).map(Question::from).collect(),
        answers: answers
            .drain(..)
            .map(|irr| from_irr(&original_input, irr))
            .collect::<Result<Vec<ResourceRecord>>>()?,
        name_servers: name_servers
            .drain(..)
            .map(|irr| from_irr(&original_input, irr))
            .collect::<Result<Vec<ResourceRecord>>>()?,
        additional_records: additional_records
            .drain(..)
            .map(|irr| from_irr(&original_input, irr))
            .collect::<Result<Vec<ResourceRecord>>>()?,
    })
}

/// Resolves all Name::Pointer records to either Name::Name's or
/// Name::ResolvedPtr's - should be given an empty HashSet as this is used to
/// track seen pointers to avoid loops.
#[instrument(skip(input))]
fn resolve_names<'a>(
    input: &[u8],
    names: &mut Vec<Name>,
    seen_ptrs: &mut HashSet<u16>,
) -> Result<()> {
    for n in names.iter_mut() {
        match n {
            Name::Pointer(ptr) => {
                if seen_ptrs.contains(ptr) {
                    return Err(MessageError::CircularReference(
                        format!(
                            "Circular reference - detected a pointer we have seen already: {}",
                            *ptr
                        )
                        .to_string(),
                    ));
                }
                seen_ptrs.insert(*ptr);
                let (_, mut names) = read_names(&input[*ptr as usize..input.len()])?;
                resolve_names(input, &mut names, seen_ptrs)?;

                *n = Name::ResolvedPtr(names);
            }
            _ => {}
        }
    }
    Ok(())
}

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
                // This however should not happen now that we recursively resolve the names.
                error!("WARNING - FOUND UNRESOLVED POINTER....SKIPPING");
            }
        }
    }
    // Remove the trailing '.'
    if name.chars().last() == Some('.') {
        name.pop();
    }
    name
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test::setup, Class, OpCode, RCode, RData, Type};
    use std::net::Ipv4Addr;

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
        assert!(!message.header.qr);
        assert_eq!(message.header.opcode, OpCode::Query);
        assert!(!message.header.aa);
        assert!(!message.header.tc);
        assert!(message.header.rd);
        assert!(!message.header.ra);
        assert!(message.header.ad);
        assert!(!message.header.cd);
        assert_eq!(message.header.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 0);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 1);

        // Question
        assert_eq!(message.questions[0].q_name, "www.google.com");
        assert_eq!(message.questions[0].q_type, Type::A);
        assert_eq!(message.questions[0].q_class, Class::IN);
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
        assert!(message.header.qr);
        assert_eq!(message.header.opcode, OpCode::Query);
        assert!(!message.header.aa);
        assert!(!message.header.tc);
        assert!(message.header.rd);
        assert!(message.header.ra);
        assert!(!message.header.ad);
        assert!(!message.header.cd);
        assert_eq!(message.header.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 0);

        // Question
        assert_eq!(message.questions[0].q_name, "www.northeastern.edu");
        assert_eq!(message.questions[0].q_type, Type::A);
        assert_eq!(message.questions[0].q_class, Class::IN);

        // Answer
        assert_eq!(message.answers[0].name, "www.northeastern.edu");
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 600);
        assert_eq!(
            message.answers[0].data,
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
        assert!(message.header.qr);
        assert_eq!(message.header.opcode, OpCode::Query);
        assert!(!message.header.aa);
        assert!(!message.header.tc);
        assert!(message.header.rd);
        assert!(message.header.ra);
        assert!(!message.header.ad);
        assert!(!message.header.cd);
        assert_eq!(message.header.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 4);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 0);

        // Question
        assert_eq!(message.questions[0].q_name, "www.microsoft.com");
        assert_eq!(message.questions[0].q_type, Type::A);
        assert_eq!(message.questions[0].q_class, Class::IN);

        // Answer 1
        assert_eq!(message.answers[0].name, "www.microsoft.com");
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 1504);
        assert_eq!(
            message.answers[0].data,
            RData::CNAME(String::from("www.microsoft.com-c-3.edgekey.net"))
        );

        // Answer 2
        assert_eq!(message.answers[1].name, "www.microsoft.com-c-3.edgekey.net");
        assert_eq!(message.answers[1].class, Class::IN);
        assert_eq!(message.answers[1].ttl, 4526);
        assert_eq!(
            message.answers[1].data,
            RData::CNAME(String::from(
                "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
            ))
        );

        // Answer 3
        assert_eq!(
            message.answers[2].name,
            "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
        );
        assert_eq!(message.answers[2].class, Class::IN);
        assert_eq!(message.answers[2].ttl, 870);
        assert_eq!(
            message.answers[2].data,
            RData::CNAME(String::from("e13678.dspb.akamaiedge.net"))
        );

        // Answer 4
        assert_eq!(message.answers[3].name, "e13678.dspb.akamaiedge.net");
        assert_eq!(message.answers[3].class, Class::IN);
        assert_eq!(message.answers[3].ttl, 5);
        assert_eq!(
            message.answers[3].data,
            RData::A(Ipv4Addr::new(23, 40, 73, 65))
        );
    }

    #[test]
    fn test_deserialize_no_compression() {
        setup();
        let input = &[
            55, 93, 129, 128, 0, 1, 0, 4, 0, 0, 0, 0, 3, 119, 119, 119, 9, 109, 105, 99, 114, 111,
            115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3, 119, 119, 119, 9, 109, 105, 99,
            114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 5, 0, 1, 0, 0, 11, 196, 0, 35, 3,
            119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99,
            45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0, 3, 119, 119, 119, 9,
            109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99, 45, 51, 7, 101,
            100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 0, 0, 5, 0, 1, 0, 0, 63, 25, 0, 58, 3,
            119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45, 99,
            45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 11, 103, 108, 111, 98,
            97, 108, 114, 101, 100, 105, 114, 6, 97, 107, 97, 100, 110, 115, 3, 110, 101, 116, 0,
            3, 119, 119, 119, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 7, 99, 111, 109, 45,
            99, 45, 51, 7, 101, 100, 103, 101, 107, 101, 121, 3, 110, 101, 116, 11, 103, 108, 111,
            98, 97, 108, 114, 101, 100, 105, 114, 6, 97, 107, 97, 100, 110, 115, 3, 110, 101, 116,
            0, 0, 5, 0, 1, 0, 0, 3, 90, 0, 28, 6, 101, 49, 51, 54, 55, 56, 4, 100, 115, 99, 98, 10,
            97, 107, 97, 109, 97, 105, 101, 100, 103, 101, 3, 110, 101, 116, 0, 6, 101, 49, 51, 54,
            55, 56, 4, 100, 115, 99, 98, 10, 97, 107, 97, 109, 97, 105, 101, 100, 103, 101, 3, 110,
            101, 116, 0, 0, 1, 0, 1, 0, 0, 0, 16, 0, 4, 23, 40, 73, 65,
        ];

        let message = Message::from_bytes(input).unwrap();

        assert_eq!(message.header.id, 14173);
        assert!(message.header.qr);
        assert_eq!(message.header.opcode, OpCode::Query);
        assert!(!message.header.aa);
        assert!(!message.header.tc);
        assert!(message.header.rd);
        assert!(message.header.ra);
        assert!(!message.header.ad);
        assert!(!message.header.cd);
        assert_eq!(message.header.rcode, RCode::NoError);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.answers.len(), 4);
        assert_eq!(message.name_servers.len(), 0);
        assert_eq!(message.additional_records.len(), 0);

        // Question
        assert_eq!(message.questions[0].q_name, "www.microsoft.com");
        assert_eq!(message.questions[0].q_type, Type::A);
        assert_eq!(message.questions[0].q_class, Class::IN);

        // Answer 1
        assert_eq!(message.answers[0].name, "www.microsoft.com");
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 3012);
        assert_eq!(
            message.answers[0].data,
            RData::CNAME(String::from("www.microsoft.com-c-3.edgekey.net"))
        );

        // Answer 2
        assert_eq!(message.answers[1].name, "www.microsoft.com-c-3.edgekey.net");
        assert_eq!(message.answers[1].class, Class::IN);
        assert_eq!(message.answers[1].ttl, 16153);
        assert_eq!(
            message.answers[1].data,
            RData::CNAME(String::from(
                "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
            ))
        );

        // Answer 3
        assert_eq!(
            message.answers[2].name,
            "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"
        );
        assert_eq!(message.answers[2].class, Class::IN);
        assert_eq!(message.answers[2].ttl, 858);
        assert_eq!(
            message.answers[2].data,
            RData::CNAME(String::from("e13678.dscb.akamaiedge.net"))
        );

        // Answer 4
        assert_eq!(message.answers[3].name, "e13678.dscb.akamaiedge.net");
        assert_eq!(message.answers[3].class, Class::IN);
        assert_eq!(message.answers[3].ttl, 16);
        assert_eq!(
            message.answers[3].data,
            RData::A(Ipv4Addr::new(23, 40, 73, 65))
        );
        println!("{:#?}", message)
    }

    #[test]
    fn test_parse_soa() {
        setup();

        let input: &[u8] = &[
            52, 123, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 5, 114, 121, 97, 110, 116, 3, 111, 114, 103,
            0, 0, 6, 0, 1, 192, 12, 0, 6, 0, 1, 0, 0, 84, 95, 0, 81, 11, 110, 115, 45, 99, 108,
            111, 117, 100, 45, 97, 49, 13, 103, 111, 111, 103, 108, 101, 100, 111, 109, 97, 105,
            110, 115, 3, 99, 111, 109, 0, 20, 99, 108, 111, 117, 100, 45, 100, 110, 115, 45, 104,
            111, 115, 116, 109, 97, 115, 116, 101, 114, 6, 103, 111, 111, 103, 108, 101, 192, 65,
            0, 0, 0, 1, 0, 0, 84, 96, 0, 0, 14, 16, 0, 3, 244, 128, 0, 0, 1, 44,
        ];

        let message = Message::from_bytes(&input).unwrap();

        let mut buf = Vec::with_capacity(1024);
        let len = message.to_bytes(&mut buf).unwrap();

        let message2 = Message::from_bytes(&buf[0..len]).unwrap();

        assert_eq!(message, message2);
    }
}
