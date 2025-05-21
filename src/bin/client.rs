use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::TRACE)
        .init();

    let local_addr: SocketAddr = "127.0.0.1:4443".parse()?;
    let server_addr: SocketAddr = "192.168.1.223:8433".parse()?;
    let remote_addr: SocketAddr = "127.0.0.1:8443".parse()?;

    h3_masque::open_udp_proxy(local_addr, server_addr, remote_addr).await?;
    info!("UDP proxy finished");
    Ok(())
}
