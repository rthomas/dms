use bytes::Bytes;
use futures::prelude::*;
use futures_util::stream::SplitSink;
use message::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;
use tracing::{error, info};

mod message;

type Result<T> = anyhow::Result<T>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let local_addr = "127.0.0.1:8053";
    let listener = UdpSocket::bind(&local_addr).await?;

    let (sink, mut stream) = UdpFramed::new(listener, BytesCodec::new()).split();
    let sink = Arc::new(Mutex::new(sink));

    loop {
        info!("Waiting to recv...");
        let (bytes, addr) = stream.next().await.unwrap()?;

        let mut sink = sink.clone();

        tokio::spawn(async move {
            match handle_request(bytes.as_ref(), &mut sink, addr).await {
                Err(e) => {
                    error!("Error handling request: {}", e);
                }
                _ => {
                    info!("Request handled!");
                }
            }
        });
    }
}

async fn handle_request(
    buf: &[u8],
    local_socket: &mut Arc<Mutex<SplitSink<UdpFramed<BytesCodec>, (Bytes, SocketAddr)>>>,
    client_addr: SocketAddr,
) -> Result<()> {
    let mut message = Message::from_bytes(buf).unwrap();
    info!("{}: {}", client_addr, message);

    modify_request(&mut message).await;

    let mut r_message = send_dns_request(&message).await?;

    modify_response(&mut r_message).await;

    let mut buf = Vec::with_capacity(1024);
    let len = r_message.to_bytes(&mut buf)?;
    info!("Sending to: {}, length: {}", client_addr, len);
    {
        local_socket
            .lock()
            .await
            .send((Bytes::copy_from_slice(&buf[0..len]), client_addr))
            .await?;
    }

    info!("Sent");
    Ok(())
}

/// Sends the Message to a dns server, returning the resulting Message.
async fn send_dns_request(msg: &Message) -> Result<Message> {
    // New socket to talk to upstream dns.
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(addr).await?;

    let remote_addr: SocketAddr = "8.8.8.8:53".parse()?;
    socket.connect(&remote_addr).await?;

    let mut buf = Vec::with_capacity(512);
    let len = msg.to_bytes(&mut buf)?;

    info!("Sending to {}", remote_addr);
    socket.send(&buf[0..len]).await?;

    let mut buf = vec![0u8; 1024];
    let len = socket.recv(&mut buf).await?;

    let r_message = match Message::from_bytes(&buf[0..len]) {
        Ok(m) => m,
        Err(e) => {
            error!("Error parsing response from upstream DNS: {}", e);
            return Err(anyhow::Error::new(e));
        }
    };
    info!("Got back: {}", r_message);
    Ok(r_message)
}

async fn modify_request(msg: &mut Message) {}

async fn modify_response(msg: &mut Message) {
    for a in msg.answers.iter_mut() {
        match a.data {
            message::RData::A(ref mut v4) => {
                println!("A: {}", v4);
                *v4 = std::net::Ipv4Addr::new(127, 0, 0, 1);
            }
            _ => {}
        }
    }
}
