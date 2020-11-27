use std::error::Error;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use message::Message;

mod message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let message = Message::parse(buf).unwrap();
    println!("Got: {:#?}\n From: {}", message, addr);
}

#[cfg(test)]
mod test {
    use super::message::Message;

    #[test]
    fn test_parse() {
        // let input: &[u8] = &[
        //     0b0000, 0b0011, // ID
        //     0b1000, 0b0001, // QR, Opcode, AA, TC, RD
        //     0b0000, 0b0000, // RA, Z, RCODE
        //     0b0000, 0b0000, // QDCOUNT
        //     0b0000, 0b0000, // ANCOUNT
        //     0b0000, 0b0000, // NSCOUNT
        //     0b0000, 0b0000, // ARCOUNT
        // ];

        let input: &[u8] = &[
            83, 202, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 6, 103, 111, 111, 103, 108,
            101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8,
            107, 120, 163, 147, 238, 31, 231, 235,
        ];

        let message = Message::parse(input).unwrap();

        println!("{:#?}", message);
    }

    #[test]
    fn test_parse_resp() {
        let input: &[u8] = &[
            0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44,
        ];

        let message = Message::parse(input).unwrap();
        println!("{:#?}", message);
    }
}
