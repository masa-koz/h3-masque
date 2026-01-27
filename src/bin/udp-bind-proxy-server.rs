use async_trait::async_trait;
use h3_msquic_async::msquic;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

struct UdpProxyServiceImpl;

#[async_trait]
impl h3_masque::server::UdpProxyService for UdpProxyServiceImpl {
    async fn authenticate(&self, req: &http::Request<()>) -> anyhow::Result<bool> {
        // Implement your authentication logic here.
        info!("Authenticating UDP proxy request: {:?}", req);
        Ok(true)
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

    let server_addr: SocketAddr = "0.0.0.0:4443".parse()?;

    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    h3_masque::server::serve_udp_bind_proxy(
        &registration,
        server_addr,
        Arc::new(UdpProxyServiceImpl),
    )
    .await?;
    info!("UDP proxy finished");
    Ok(())
}
