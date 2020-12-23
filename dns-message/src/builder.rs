use crate::{Class, Header, Message, OpCode, Question, RCode, RData, ResourceRecord, Type};
use std::default::Default;

#[derive(Debug, Default)]
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
    pub fn new() -> Self {
        Default::default()
    }

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

    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn qr(mut self, qr: bool) -> Self {
        self.qr = qr;
        self
    }

    pub fn opcode(mut self, opcode: OpCode) -> Self {
        self.opcode = opcode;
        self
    }

    pub fn aa(mut self, aa: bool) -> Self {
        self.aa = aa;
        self
    }

    pub fn tc(mut self, tc: bool) -> Self {
        self.tc = tc;
        self
    }

    pub fn rd(mut self, rd: bool) -> Self {
        self.rd = rd;
        self
    }

    pub fn ra(mut self, ra: bool) -> Self {
        self.ra = ra;
        self
    }

    pub fn ad(mut self, ad: bool) -> Self {
        self.ad = ad;
        self
    }

    pub fn cd(mut self, cd: bool) -> Self {
        self.cd = cd;
        self
    }

    pub fn rcode(mut self, rcode: RCode) -> Self {
        self.rcode = rcode;
        self
    }

    pub fn question(mut self, question: Question) -> Self {
        self.questions.push(question);
        self
    }

    pub fn answer(mut self, answer: ResourceRecord) -> Self {
        self.answers.push(answer);
        self
    }

    pub fn name_server(mut self, ns: ResourceRecord) -> Self {
        self.name_servers.push(ns);
        self
    }

    pub fn additional_record(mut self, ar: ResourceRecord) -> Self {
        self.additional_records.push(ar);
        self
    }
}

#[derive(Debug, Default)]
pub struct QuestionBuilder {
    q_name: String,
    q_type: Type,
    q_class: Class,
}

impl QuestionBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn build(self) -> Question {
        Question {
            q_name: self.q_name,
            q_type: self.q_type,
            q_class: self.q_class,
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.q_name = name.to_string();
        self
    }

    pub fn q_type(mut self, t: Type) -> Self {
        self.q_type = t;
        self
    }

    pub fn class(mut self, cls: Class) -> Self {
        self.q_class = cls;
        self
    }
}

#[derive(Debug)]
pub struct ResourceRecordBuilder {
    name: String,
    data: RData,
    class: Class,
    ttl: u32,
}

impl ResourceRecordBuilder {
    pub fn new(name: &str, data: RData) -> Self {
        Self {
            name: name.to_string(),
            data: data,
            class: Default::default(),
            ttl: Default::default(),
        }
    }

    pub fn build(self) -> ResourceRecord {
        ResourceRecord {
            name: self.name,
            data: self.data,
            class: self.class,
            ttl: self.ttl,
        }
    }

    pub fn class(mut self, cls: Class) -> Self {
        self.class = cls;
        self
    }

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
