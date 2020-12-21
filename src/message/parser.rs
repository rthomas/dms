use crate::message::error::MessageError;
use crate::message::Result;
use crate::message::{
    Class, Header, Message, OpCode, Question, RCode, RData, ResourceRecord, Type,
};
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::collections::HashSet;
use std::net::Ipv4Addr;
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
        _ => RData::Raw(irr.rtype.into(), irr.rdata),
    };

    Ok(ResourceRecord {
        name: flatten_to_string(&irr.name),
        r_type: rdata,
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
