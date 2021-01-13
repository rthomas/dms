use dns_message::Message;
use futures::prelude::*;

use std::net::SocketAddr;

use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;
use tracing::{error, info, warn};

type Result<T> = anyhow::Result<T>;

pub(crate) struct Server {
    local_addr: SocketAddr,
    mod_req: Option<fn(&mut Message)>,
    mod_resp: Option<fn(&mut Message)>,
}

impl Server {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            mod_req: None,
            mod_resp: None,
        }
    }

    pub fn mod_req(&mut self, mod_req: fn(&mut Message)) {
        self.mod_req = Some(mod_req);
    }

    pub fn mod_resp(&mut self, mod_resp: fn(&mut Message)) {
        self.mod_resp = Some(mod_resp);
    }

    pub async fn run(&self) -> Result<()> {
        let listener = UdpSocket::bind(&self.local_addr).await?;

        let (sink, mut stream) = UdpFramed::new(listener, BytesCodec::new()).split();
        let sink = Arc::new(Mutex::new(sink));

        loop {
            info!("Waiting to recv...");
            let (bytes, addr) = match stream.next().await {
                Some(Ok((b, a))) => (b, a),
                Some(Err(e)) => {
                    error!("Error getting next value in stream: {}", e);
                    continue;
                }
                None => {
                    warn!("No value available from stream, closing");
                    return Ok(());
                }
            };

            let sink = sink.clone();

            // Pull these out so that we don't need to worry about referencing self in the spawned task.
            let mod_req = self.mod_req;
            let mod_resp = self.mod_resp;

            tokio::spawn(async move {
                let mut message = Message::from_bytes(bytes.as_ref()).unwrap();
                info!("{}: {}", addr, message);

                if let Some(mod_req) = mod_req {
                    mod_req(&mut message);
                }

                let mut r_message = match send_dns_request(&message).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Could not send DNS request: {}", e);
                        return;
                    }
                };

                if let Some(mod_resp) = mod_resp {
                    mod_resp(&mut r_message);
                }

                let mut buf = Vec::with_capacity(1024);
                let len = match r_message.to_bytes(&mut buf) {
                    Ok(len) => len,
                    Err(e) => {
                        error!("Could not serialize message: {}", e);
                        return;
                    }
                };
                info!("Sending to: {}, length: {}", addr, len);
                {
                    match sink.lock().await.send((buf.into(), addr)).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Error sending buffer to client: {}", e);
                            return;
                        }
                    }
                }

                info!("Sent");
            });
        }
    }
}

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
