use h3_msquic_async::msquic;
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

    let local_bind_addr: SocketAddr = "127.0.0.1:4567".parse()?;
    let server_addr: SocketAddr = "153.127.33.247:4443".parse()?;
    let target_addr: Option<SocketAddr> = None;

    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    let (_handle, mut event_receiver) = h3_masque::client::connect_udp_bind_proxy(&registration, local_bind_addr, server_addr, target_addr).await?;
    while let Some(event) = event_receiver.recv().await {
        match event {
            h3_masque::client::BoundProxyEvent::NotifyPublicAddress(public_addr ) => {
                info!("Received public addresses: {}", public_addr);
            }
            h3_masque::client::BoundProxyEvent::NotifyObservedAddress { local_address, observed_address }   => {
                info!("Observed address for local address {} is {}", local_address, observed_address);
            }
        }
    }
    info!("UDP proxy finished");
    Ok(())
}
