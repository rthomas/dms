use crate::message::error::MessageError;
use crate::message::flatten_to_string;
use crate::message::message::{
    Class, Flags, Header, Message, OpCode, Question, RCode, RData, ResourceRecord, Type,
};
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::IResult;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tracing::{instrument, trace};

type Result<T> = std::result::Result<T, MessageError>;

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
pub(crate) enum Name {
    Name(String),
    Pointer(u16),
    ResolvedPtr(Vec<Name>),
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
        let rdata = match irr.rtype {
            Type::A => RData::A(Ipv4Addr::new(
                irr.rdata[0],
                irr.rdata[1],
                irr.rdata[2],
                irr.rdata[3],
            )),
            _ => RData::Raw(irr.rdata),
        };

        ResourceRecord {
            name: flatten_to_string(&irr.name),
            rtype: irr.rtype,
            class: irr.class,
            ttl: irr.ttl,
            rdata: rdata,
        }
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
    map_res(take_bytes(2usize), |input| -> Result<Flags> {
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
    })(input)
}

#[instrument(skip(input))]
fn read_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_res(take_bytes(12usize), |input| -> Result<Header> {
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

    let (input, rdata) = take_bytes(rdlength)(input)?;
    trace!("rdata: {:?}", rdata);
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
