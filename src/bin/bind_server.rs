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

    let server_addr: SocketAddr = "127.0.0.1:4443".parse()?;

    h3_masque::server::serve_udp_bind_proxy(server_addr).await?;
    info!("UDP proxy finished");
    Ok(())
}
