use std::error::Error;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use message::Message;

mod message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let addr = "127.0.0.1:8053";
    let listener = UdpSocket::bind(&addr).await?;

    loop {
        println!("Waiting to accept...");
        // RFC1035 - Limit length of 512 bytes, so just double it.
        let mut buf = [0; 1024];
        let (len, addr) = listener.recv_from(&mut buf).await?;
        tokio::spawn(async move {
            handle_request(&buf[0..len], addr);
        });
    }
}

fn handle_request(buf: &[u8], addr: SocketAddr) {
    let message = Message::from_bytes(buf).unwrap();
    println!("Got: {:#?}\n From: {}", message, addr);
}

#[cfg(test)]
mod test {
    use super::message::Message;

    #[test]
    fn test_parse_question() {
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
        assert!(!message.header.flags.qr);
        assert_eq!(message.header.flags.opcode, crate::message::OpCode::Query);
        assert!(!message.header.flags.aa);
        assert!(!message.header.flags.tc);
        assert!(message.header.flags.rd);
        assert!(!message.header.flags.ra);
        assert!(message.header.flags.ad);
        assert!(!message.header.flags.cd);
        assert_eq!(message.header.flags.rcode, crate::message::RCode::NoError);
        assert_eq!(message.header.qd_count, 1);
        assert_eq!(message.header.an_count, 0);
        assert_eq!(message.header.ns_count, 0);
        assert_eq!(message.header.ar_count, 1);

        // Question
        assert_eq!(message.questions[0].qname, "www.google.com");
        assert_eq!(message.questions[0].qtype, crate::message::Type::A);
        assert_eq!(message.questions[0].qclass, crate::message::Class::IN);
    }

    #[test]
    fn test_parse_answer() {
        let input: &[u8] = &[
            0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44,
        ];

        let message = Message::from_bytes(input).unwrap();

        // Header
        assert_eq!(message.header.id, 56130);
        assert!(message.header.flags.qr);
        assert_eq!(message.header.flags.opcode, crate::message::OpCode::Query);
        assert!(!message.header.flags.aa);
        assert!(!message.header.flags.tc);
        assert!(message.header.flags.rd);
        assert!(message.header.flags.ra);
        assert!(!message.header.flags.ad);
        assert!(!message.header.flags.cd);
        assert_eq!(message.header.flags.rcode, crate::message::RCode::NoError);
        assert_eq!(message.header.qd_count, 1);
        assert_eq!(message.header.an_count, 1);
        assert_eq!(message.header.ns_count, 0);
        assert_eq!(message.header.ar_count, 0);

        // Question
        assert_eq!(message.questions[0].qname, "www.northeastern.edu");
        assert_eq!(message.questions[0].qtype, crate::message::Type::A);
        assert_eq!(message.questions[0].qclass, crate::message::Class::IN);

        // Answer
        assert_eq!(message.answers[0].name, "www.northeastern.edu");
        assert_eq!(message.answers[0].rtype, crate::message::Type::A);
        assert_eq!(message.answers[0].class, crate::message::Class::IN);
        assert_eq!(message.answers[0].ttl, 600);
        assert_eq!(message.answers[0].rdata, vec![155, 33, 17, 68]);
    }

    #[test]
    fn test_deserialize_serialize_deserialize() {
        tracing_subscriber::fmt::init();

        let input: &[u8] = &[
            0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44,
        ];

        let message = Message::from_bytes(input).unwrap();
        // println!("{:#?}", message);

        let mut buf = Vec::new();
        message.to_bytes(&mut buf).unwrap();
        let message2 = Message::from_bytes(&buf[..]).unwrap();
        assert_eq!(message, message2);
    }
}
