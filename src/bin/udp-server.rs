use tokio::net::UdpSocket;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let sock = UdpSocket::bind("127.0.0.1:8443").await?;
    let mut buf = [0; 2048];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        info!("{:?} bytes received from {:?}", len, addr);

        let len = sock.send_to(&buf[..len], addr).await?;
        info!("{:?} bytes sent", len);
    }
}
