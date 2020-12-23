use crate::{parser, Header, Question, ResourceRecord, Result};
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
        write!(f, "Query [")?;
        for (i, q) in self.questions.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}({})", q.q_name, q.q_type)?;
        }
        write!(f, "]")?;
        if self.header.qr {
            write!(f, " - Response [")?;
            for (i, a) in self.answers.iter().enumerate() {
                if i != 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{} => {}", a.name, a.data)?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test::setup;

    #[test]
    pub fn test_to_bytes_from_bytes() {
        setup();

        use crate::{
            Message, MessageBuilder, OpCode, QuestionBuilder, RCode, RData, ResourceRecordBuilder,
            Type,
        };
        use std::net::Ipv4Addr;

        let message = MessageBuilder::new()
            .id(1234)
            .qr(true)
            .aa(true)
            .ad(true)
            .opcode(OpCode::Status)
            .rcode(RCode::ServerFailure)
            .question(
                QuestionBuilder::new()
                    .name("www.google.com")
                    .q_type(Type::A)
                    .build(),
            )
            .answer(
                ResourceRecordBuilder::new(
                    "www.google.com",
                    RData::A(Ipv4Addr::new(142, 250, 71, 68)),
                )
                .ttl(5678)
                .build(),
            )
            .answer(
                ResourceRecordBuilder::new(
                    "www.google.com",
                    RData::A(Ipv4Addr::new(216, 58, 199, 36)),
                )
                .ttl(5678)
                .build(),
            )
            .build();
        let mut buf = Vec::new();
        let message_len = message.to_bytes(&mut buf).unwrap();
        let message2 = Message::from_bytes(&buf[0..message_len]).unwrap();

        assert_eq!(message, message2);
    }
}
