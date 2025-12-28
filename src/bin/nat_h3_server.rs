use std::{future::poll_fn, net::SocketAddr, path::PathBuf, sync::Arc};

use argh::FromArgs;
use bytes::{Bytes, BytesMut};
use h3::{quic::BidiStream, server::RequestStream};
use h3_msquic_async::{msquic, msquic_async};
use http::{Request, StatusCode};
use tokio::sync::mpsc;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{error, info};

#[derive(FromArgs, Clone)]
/// server args
pub struct CmdOptions {
    /// root path
    #[argh(option)]
    root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let cmd_opts: CmdOptions = argh::from_env();
    let root = Arc::new(cmd_opts.root);

    let local_bind_addr: SocketAddr = "127.0.0.1:8443".parse()?;
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

    let alpn = [msquic::BufferRef::from("h3")];

    // create msquic-async listener
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(10000)
                .set_KeepAliveIntervalMs(1000)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled()
                .set_ServerMigrationEnabled(),
                // .set_AddAddressMode(msquic::AddAddressMode::Manual),
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

    let addr: SocketAddr = "127.0.0.1:8443".parse()?;
    listener.start(&alpn, Some(addr))?;
    let server_addr = listener.local_addr()?;

    info!("listening on {}", server_addr);

    let Some((local_address, observed_address)) = observed_receiver.recv().await else {
        error!("did not receive observed address");
        return Ok(());
    };

    // handle incoming connections and requests

    while let Ok(conn) = listener.accept().await {
        info!("new connection established");
        let local_address = local_address.clone();
        let observed_address = observed_address.clone();
        let unspecified_address = "0.0.0.0:0".parse::<SocketAddr>()?;
        conn.add_local_addr(unspecified_address.clone(), unspecified_address.clone())?;
        info!(
            "added local address {} with observed address {}",
            local_address, observed_address
        );
        let event_handle = {
            let conn = conn.clone();
            // let mut new_remote_address = None;
            tokio::spawn(async move {
                while let Ok(event) = poll_fn(|cx| conn.poll_event(cx)).await {
                    match event {
                        msquic_async::ConnectionEvent::NotifyObservedAddress {
                            local_address,
                            observed_address,
                        } => {
                            info!(
                                "local address: {}, observed address: {}",
                                local_address, observed_address
                            );
                            // conn.add_local_addr(local_address.clone(), local_address)?;
                        }
                        msquic_async::ConnectionEvent::NotifyRemoteAddressAdded {
                            address,
                            sequence_number,
                        } => {
                            info!(
                                "remote address: {}, sequence number: {}",
                                address, sequence_number
                            );
                            // conn.create_path(unspecified_address.clone(), address.clone())?;
                        }
                        msquic_async::ConnectionEvent::PathValidated {
                            local_address,
                            remote_address,
                        } => {
                            info!(
                                "path validated local address: {}, remote address: {}",
                                local_address, remote_address
                            );
                            if !local_address.ip().is_loopback() {
                                conn.activate_path(local_address, remote_address.clone())?;
                                // new_remote_address = Some(remote_address);
                            }
                        }
                        msquic_async::ConnectionEvent::NotifyRemoteAddressRemoved {
                            sequence_number,
                        } => {
                            info!(
                                "remote address removed with sequence number: {}",
                                sequence_number
                            );
                            // if let Some(addr) = &new_remote_address {
                            //     conn.remove_remote_addr(addr.clone())?;
                            // }
                        }
                    }
                }
                anyhow::Ok(())
            })
        };
        let root = root.clone();
        tokio::spawn(async move {
            let mut h3_conn =
                h3::server::Connection::new(h3_msquic_async::Connection::new(conn)).await?;
            loop {
                match h3_conn.accept().await {
                    Ok(Some(req_resolver)) => {
                        let (req, stream) = match req_resolver.resolve_request().await {
                            Ok(req) => req,
                            Err(err) => {
                                error!("error resolving request: {}", err);
                                continue;
                            }
                        };
                        info!("new request: {:#?}", req);

                        let root = root.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_request(req, stream, root).await {
                                error!("handling request failed: {}", e);
                            }
                        });
                    }

                    // indicating no more streams to be received
                    Ok(None) => {
                        break;
                    }

                    Err(err) => {
                        error!("error on accept {}", err);
                        break;
                    }
                }
            }
            event_handle.await??;
            anyhow::Ok(())
        });
    }

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
) -> anyhow::Result<()>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        Some(root) => {
            let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
            match File::open(&to_serve).await {
                Ok(file) => (StatusCode::OK, Some(file)),
                Err(e) => {
                    error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
                    (StatusCode::NOT_FOUND, None)
                }
            }
        }
    };

    let resp = http::Response::builder().status(status).body(())?;

    match stream.send_response(resp).await {
        Ok(_) => {
            info!("successfully respond to connection");
        }
        Err(err) => {
            error!("unable to send response to connection peer: {:?}", err);
        }
    }

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    Ok(stream.finish().await?)
}
