use h3_msquic_async::{msquic, msquic_async};
use std::future::poll_fn;
use std::net::SocketAddr;
use std::mem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info};

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

    let (_handle, mut event_receiver) = h3_masque::client::connect_udp_bind_proxy(
        &registration,
        local_bind_addr,
        server_addr,
        target_addr,
    )
    .await?;
    let (observed_sender, mut observed_receiver) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            match event {
                h3_masque::client::BoundProxyEvent::NotifyPublicAddress(public_addr) => {
                    info!("Received public addresses: {}", public_addr);
                }
                h3_masque::client::BoundProxyEvent::NotifyObservedAddress {
                    local_address,
                    observed_address,
                } => {
                    info!(
                        "Observed address for local address {} is {}",
                        local_address, observed_address
                    );
                    observed_sender
                        .send((local_address, observed_address))
                        .await
                        .unwrap();
                }
            }
        }
    });

    let alpn = [msquic::BufferRef::from("sample")];

    // create msquic-async listener
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(10000)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    #[cfg(any(not(windows), feature = "quictls"))]
    {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let cert = include_bytes!("../cert.pem");
        let key = include_bytes!("../key.pem");

        let mut cert_file = NamedTempFile::new()?;
        cert_file.write_all(cert)?;
        let cert_path = cert_file.into_temp_path();
        let cert_path = cert_path.to_string_lossy().into_owned();

        let mut key_file = NamedTempFile::new()?;
        key_file.write_all(key)?;
        let key_path = key_file.into_temp_path();
        let key_path = key_path.to_string_lossy().into_owned();

        let cred_config = msquic::CredentialConfig::new().set_credential(
            msquic::Credential::CertificateFile(msquic::CertificateFile::new(key_path, cert_path)),
        );

        configuration.load_credential(&cred_config)?;
    }

    #[cfg(all(windows, not(feature = "quictls")))]
    {
        use schannel::RawPointer;
        use schannel::cert_context::{CertContext, KeySpec};
        use schannel::cert_store::{CertAdd, Memory};
        use schannel::crypt_prov::{AcquireOptions, ProviderType};

        let cert = include_str!("../cert.pem");
        let key = include_bytes!("../key.pem");

        let mut store = Memory::new().unwrap().into_store();

        let name = String::from("msquic-async-example");

        let cert_ctx = CertContext::from_pem(cert).unwrap();

        let mut options = AcquireOptions::new();
        options.container(&name);

        let type_ = ProviderType::rsa_full();

        let mut container = match options.acquire(type_) {
            Ok(container) => container,
            Err(_) => options.new_keyset(true).acquire(type_).unwrap(),
        };
        container.import().import_pkcs8_pem(key).unwrap();

        cert_ctx
            .set_key_prov_info()
            .container(&name)
            .type_(type_)
            .keep_open(true)
            .key_spec(KeySpec::key_exchange())
            .set()
            .unwrap();

        let context = store.add_cert(&cert_ctx, CertAdd::Always).unwrap();

        let cred_config = msquic::CredentialConfig::new().set_credential(
            msquic::Credential::CertificateContext(unsafe { context.as_ptr() }),
        );

        configuration.load_credential(&cred_config)?;
    };

    let listener = msquic_async::Listener::new(&registration, configuration)?;

    let addr: SocketAddr = "127.0.0.1:4567".parse()?;
    listener.start(&alpn, Some(addr))?;
    let server_addr = listener.local_addr()?;

    info!("listening on {}", server_addr);

    let Some((local_address, observed_address)) = observed_receiver.recv().await else {
        error!("did not receive observed address");
        return Ok(());
    };
    // handle incoming connections and streams
    while let Ok(conn) = listener.accept().await {
        info!("new connection established");
        let local_address = local_address.clone();
        let observed_address = observed_address.clone();
        tokio::spawn(async move {
            conn.add_local_addr(local_address, observed_address)?;
            loop {
                match conn.accept_inbound_stream().await {
                    Ok(mut stream) => {
                        info!("new stream id: {}", stream.id().expect("stream id"));
                        let mut buf = [0u8; 1024];
                        let len = stream.read(&mut buf).await?;
                        info!(
                            "reading from stream: {}",
                            String::from_utf8_lossy(&buf[0..len])
                        );
                        stream.write_all(&buf[0..len]).await?;
                        poll_fn(|cx| stream.poll_finish_write(cx)).await?;
                        mem::drop(stream);
                    }
                    Err(err) => {
                        error!("error on accept stream: {}", err);
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });
    }

    info!("UDP proxy finished");
    Ok(())
}
