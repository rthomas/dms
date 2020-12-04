use message::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info};

mod message;

type Result<T> = anyhow::Result<T>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let local_addr = "127.0.0.1:8053";
    let listener = Arc::new(UdpSocket::bind(&local_addr).await?);

    loop {
        println!("Waiting to accept...");
        // RFC1035 - Limit length of 512 bytes, so just double it.
        let mut buf = [0; 1024];
        let (len, addr) = listener.recv_from(&mut buf).await?;
        let l_clone = listener.clone();
        tokio::spawn(async move {
            match handle_request(&buf[0..len], &l_clone, addr).await {
                Err(e) => {
                    error!("Error handling request: {}", e);
                }
                _ => (),
            }
        });
    }
}

async fn handle_request(
    buf: &[u8],
    local_socket: &UdpSocket,
    client_addr: SocketAddr,
) -> Result<()> {
    let message = Message::from_bytes(buf).unwrap();
    info!("{}: {}", client_addr, message);

    let r_message = send_dns_request(&message).await?;

    let mut buf = Vec::with_capacity(1024);
    r_message.to_bytes(&mut buf)?;
    local_socket.connect(&client_addr).await?;
    local_socket.send(&buf).await?;
    Ok(())
}

/// Sends the Message to a dns server, returning the resulting Message.
async fn send_dns_request(msg: &Message) -> Result<Message> {
    // New socket to talk to upstream dns.
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(addr).await?;

    let remote_addr: SocketAddr = "192.168.1.1:53".parse()?;
    socket.connect(&remote_addr).await?;

    let mut buf = Vec::with_capacity(1024);
    msg.to_bytes(&mut buf)?;

    info!("Sending to {}", remote_addr);
    socket.send(&buf).await?;

    let mut buf = vec![0u8; 1024];
    socket.recv(&mut buf).await?;

    let r_message = Message::from_bytes(&buf).unwrap();
    info!("Got back: {}", r_message);
    Ok(r_message)
}
