use crate::{Class, Header, Message, OpCode, Question, RCode, RData, ResourceRecord, Type};
use std::default::Default;

#[derive(Debug, Default)]
/// Helper to build a [`Message`] type.
///
/// Default implementations will be used for all types if they are not specified
/// during construction.
pub struct MessageBuilder {
    id: u16,
    qr: bool,
    opcode: OpCode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    ad: bool,
    cd: bool,
    rcode: RCode,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    name_servers: Vec<ResourceRecord>,
    additional_records: Vec<ResourceRecord>,
}

impl MessageBuilder {
    /// Create a new [`MessageBuilder`] with the default values for all fields.
    pub fn new() -> Self {
        Default::default()
    }

    /// Consume the [`MessageBuilder`] and produce a [`Message`].
    pub fn build(self) -> Message {
        Message {
            header: Header {
                id: self.id,
                qr: self.qr,
                opcode: self.opcode,
                aa: self.aa,
                tc: self.tc,
                rd: self.rd,
                ra: self.ra,
                ad: self.ad,
                cd: self.cd,
                rcode: self.rcode,
            },
            questions: self.questions,
            answers: self.answers,
            name_servers: self.name_servers,
            additional_records: self.additional_records,
        }
    }

    /// RFC1035 - A 16 bit identifier assigned by the program that generates any kind of
    /// query.  This identifier is copied the corresponding reply and can be
    /// used by the requester to match up replies to outstanding queries.
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Sets the `qr` bit on the message header.
    ///
    /// This is to indicate whether the message is a query response or not.
    pub fn qr(mut self, qr: bool) -> Self {
        self.qr = qr;
        self
    }

    /// Set the [`OpCode'] for the DNS Message.
    pub fn opcode(mut self, opcode: OpCode) -> Self {
        self.opcode = opcode;
        self
    }

    /// RFC1035 - Authoritative Answer - this bit is valid in responses, and specifies
    /// that the responding name server is an authority for the domain name in
    /// question section.
    pub fn aa(mut self, aa: bool) -> Self {
        self.aa = aa;
        self
    }

    /// RFC1035 - TrunCation - specifies that this message was truncated due to length
    /// greater than that permitted on the transmission channel.
    pub fn tc(mut self, tc: bool) -> Self {
        self.tc = tc;
        self
    }

    /// RFC1035 - Recursion Desired - this bit may be set in a query and is copied into
    /// the response.  If RD is set, it directs the name server to pursue the
    /// query recursively.
    pub fn rd(mut self, rd: bool) -> Self {
        self.rd = rd;
        self
    }

    /// RFC1035 - Recursion Available - this be is set or cleared in a response, and
    /// denotes whether recursive query support is available in the name server.
    pub fn ra(mut self, ra: bool) -> Self {
        self.ra = ra;
        self
    }

    /// RFC2535 - The AD (authentic data) bit indicates in a response that all
    /// the data included in the answer and authority portion of the response
    /// has been authenticated by the server according to the policies of that
    /// server.
    pub fn ad(mut self, ad: bool) -> Self {
        self.ad = ad;
        self
    }

    /// RFC2535 - The CD (checking disabled) bit indicates in a query that
    /// Pending (non-authenticated) data is acceptable to the resolver sending
    /// the query.
    pub fn cd(mut self, cd: bool) -> Self {
        self.cd = cd;
        self
    }

    /// The response code for the DNS message.
    pub fn rcode(mut self, rcode: RCode) -> Self {
        self.rcode = rcode;
        self
    }

    /// Add a [`Question`] to the questions section.
    pub fn question(mut self, question: Question) -> Self {
        self.questions.push(question);
        self
    }

    /// Add a [`ResourceRecord`] to the answers section.
    pub fn answer(mut self, answer: ResourceRecord) -> Self {
        self.answers.push(answer);
        self
    }

    /// Add a [`ResourceRecord`] to the name servers section.
    pub fn name_server(mut self, ns: ResourceRecord) -> Self {
        self.name_servers.push(ns);
        self
    }

    /// Add a [`ResourceRecord`] to the additional records section.
    pub fn additional_record(mut self, ar: ResourceRecord) -> Self {
        self.additional_records.push(ar);
        self
    }
}

#[derive(Debug, Default)]
/// A builder for the [`Question`] struct.
pub struct QuestionBuilder {
    q_name: String,
    q_type: Type,
    q_class: Class,
}

impl QuestionBuilder {
    /// Create a new [`QuestionBuilder`] using the default values for each
    /// field.
    pub fn new() -> Self {
        Default::default()
    }

    /// Consumes the [`QuestionBuilder`] to produce a [`Question`].
    pub fn build(self) -> Question {
        Question {
            q_name: self.q_name,
            q_type: self.q_type,
            q_class: self.q_class,
        }
    }

    /// Sets the domain name for the [`Question`]. Each label section must be of
    /// length 63 or less.
    pub fn name(mut self, name: &str) -> Self {
        self.q_name = name.to_string();
        self
    }

    /// Sets the [`Type`] of this [`Question`] - the default is [`Type::A`].
    pub fn q_type(mut self, t: Type) -> Self {
        self.q_type = t;
        self
    }

    /// Sets the [`Class`] for this [`Question`] - the default is [`Class::IN`].
    pub fn class(mut self, cls: Class) -> Self {
        self.q_class = cls;
        self
    }
}

#[derive(Debug)]
/// A builder for the [`ResourceRecord`] struct.
pub struct ResourceRecordBuilder {
    name: String,
    data: RData,
    class: Class,
    ttl: u32,
}

impl ResourceRecordBuilder {
    /// Creates a new [`ResourceRecordBuilder`] - a [`ResourceRecord`] must have
    /// a `name` and [`RData`].    
    pub fn new(name: &str, data: RData) -> Self {
        Self {
            name: name.to_string(),
            data: data,
            class: Default::default(),
            ttl: Default::default(),
        }
    }

    /// Consumes the [`ResourceRecordBuilder`] to produce a [`ResourceRecord`].
    pub fn build(self) -> ResourceRecord {
        ResourceRecord {
            name: self.name,
            data: self.data,
            class: self.class,
            ttl: self.ttl,
        }
    }

    /// Sets the [`Class`] of the [`ResourceRecord`] - the default is
    /// [`Class::IN`].
    pub fn class(mut self, cls: Class) -> Self {
        self.class = cls;
        self
    }

    /// Sets the `ttl` of the [`ResourceRecord`] - the default is `0u32`.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_message_builder() {
        let builder = MessageBuilder::new();
        let message = builder
            .id(1234)
            .qr(true)
            .opcode(OpCode::Status)
            .question(
                QuestionBuilder::new()
                    .name("www.google.com")
                    .q_type(Type::CNAME)
                    .build(),
            )
            .answer(
                ResourceRecordBuilder::new(
                    "www.google.com",
                    RData::CNAME("ns1.google.com".to_string()),
                )
                .ttl(3600)
                .build(),
            )
            .build();

        assert_eq!(message.header.id, 1234);
        assert!(message.header.qr);
        assert_eq!(message.header.opcode, OpCode::Status);
        assert_eq!(message.questions[0].q_name, "www.google.com");
        assert_eq!(message.questions[0].q_type, Type::CNAME);
        assert_eq!(message.questions[0].q_class, Class::IN);
        assert_eq!(message.answers[0].name, "www.google.com");
        assert_eq!(
            message.answers[0].data,
            RData::CNAME("ns1.google.com".to_string())
        );
        assert_eq!(message.answers[0].class, Class::IN);
        assert_eq!(message.answers[0].ttl, 3600);
    }
}
