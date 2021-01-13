mod server;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let local_addr = "127.0.0.1:8053";
    let mut server = server::Server::new(local_addr.parse()?);

    server.mod_req(|m| {
        tracing::info!("Message request: {}", m);
    });

    server.mod_resp(|m| {
        tracing::info!("Message response: {}", m);
    });

    server.run().await
}
