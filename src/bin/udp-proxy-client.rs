use async_trait::async_trait;
use h3_msquic_async::msquic;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

struct UdpProxyClientServiceImpl;

#[async_trait]
impl h3_masque::client::UdpProxyClientService for UdpProxyClientServiceImpl {
    async fn event(&self, event: h3_masque::client::UdpProxyClientEvent) -> anyhow::Result<()> {
        // Implement your authentication logic here.
        info!("UDP proxy event: {:?}", event);
        Ok(())
    }
}

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

    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    h3_masque::client::connect_udp_proxy(
        &registration,
        local_addr,
        server_addr,
        remote_addr,
        Arc::new(UdpProxyClientServiceImpl),
    )
    .await?;

    info!("UDP proxy finished");
    Ok(())
}
