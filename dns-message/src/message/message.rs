use crate::message::parser;
use crate::message::{Header, Question, ResourceRecord, Result};
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
    use super::*;
    use crate::message::{Class, OpCode, RCode, RData, Type};
    use std::net::Ipv4Addr;
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
    pub fn test_serialize_deserialize() {
        setup();

        use crate::message::{MessageBuilder, QuestionBuilder, ResourceRecordBuilder};

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
