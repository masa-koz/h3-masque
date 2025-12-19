use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let local_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server_addr: SocketAddr = "127.0.0.1:4443".parse()?;
    let remote_addr: SocketAddr = "127.0.0.1:4567".parse()?;

    h3_masque::open_udp_proxy(local_addr, server_addr, remote_addr).await?;
    info!("UDP proxy finished");
    Ok(())
}
