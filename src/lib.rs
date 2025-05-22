use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::{
    error::{ConnectionError, StreamError},
    ext::Protocol,
    proto::stream::StreamId,
    quic::{self, BidiStream},
    server::RequestStream,
};
use h3_datagram::{
    datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt},
    quic_traits,
};
use h3_msquic_async::{msquic, msquic_async};
use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info};

pub async fn open_udp_proxy(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(local_addr).await?;
    let local_addr = socket.local_addr()?;
    info!("local address: {}", local_addr);

    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    let alpn = [msquic::BufferRef::from("h3")];
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(100_000)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;
    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;

    let conn = msquic_async::Connection::new(&registration)?;
    conn.start(
        &configuration,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await?;

    let handle = tokio::spawn(async move {
        let h3_conn = h3_msquic_async::Connection::new(conn);

        let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

        let mut datagrma_reader = driver.get_datagram_reader();
        let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
        let (datagram_tx_sender, mut datagram_tx_receiver) = mpsc::channel(1);

        let drive = tokio::spawn(async move {
            loop {
                tokio::select! {
                    error = poll_fn(|cx| driver.poll_close(cx)) => {
                        info!("driver closed");
                        return Err::<(), ConnectionError>(error);
                    },
                    stream_id = stream_id_receiver.recv() => {
                        if let Some(stream_id) = stream_id {
                            let datagram_sender = driver.get_datagram_sender(stream_id);
                            datagram_tx_sender.send(datagram_sender).await.unwrap();
                        }
                    }
                }
            }
        });

        let request = async move {
            info!("sending request ...");

            let req = http::request::Request::builder()
                .method("CONNECT")
                .uri(format!(
                    "https://{}/{}",
                    server_addr,
                    socketaddr_to_connect_udp_path(&remote_addr)
                ))
                .header("authorization", "dummy-authorization")
                .extension(Protocol::CONNECT_UDP)
                .body(())?;

            // sending request results in a bidirectional stream,
            // which is also used for receiving response
            let mut stream = send_request.send_request(req).await?;

            info!("request sent, stream id: {}", stream.id());

            info!("receiving response ...");

            let resp = stream.recv_response().await?;

            info!("response: {:?} {}", resp.version(), resp.status());
            info!("headers: {:#?}", resp.headers());

            stream_id_sender.send(stream.id()).await?;
            let mut datagram_sender = datagram_tx_receiver.recv().await.unwrap();

            let mut client_addr = None;
            let mut buf = [0; 65535];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        let len = match res {
                            Ok((len, addr)) => {
                                info!("received datagram from {}: {:?}", addr, &buf[..len]);
                                client_addr = Some(addr);
                                len
                            }
                            Err(err) => {
                                error!("failed to receive datagram: {:?}", err);
                                break;
                            }
                        };
                        let mut datagram = BytesMut::with_capacity(1 + len);
                        datagram.put_u8(0); // 1 byte for datagram header
                        datagram.put_slice(&buf[..len]);
                        match datagram_sender.send_datagram(datagram.freeze()) {
                            Ok(_) => {
                                info!("sent datagram to stream {}", stream.id());
                            }
                            Err(err) => {
                                error!("failed to send datagram: {:?}", err);
                                continue;
                            }
                        }
                    }
                    datagram = datagrma_reader.read_datagram() => {
                        let datagram = match datagram {
                            Ok(datagram) => datagram,
                            Err(err) => {
                                error!("failed to receive datagram: {:?}", err);
                                break;
                            }
                        };
                        info!("received datagram: {:?}", datagram);
                        let datagram = datagram.into_payload();
                        let (context_id, payload) = decode_var_int(datagram.chunk());
                        if context_id == 0 {
                            if let Err(err) = socket.send_to(payload, client_addr.as_ref().map(|a| a.clone()).unwrap()).await {
                                error!("failed to send datagram: {:?}", err);
                                continue;
                            }
                        } else {
                            info!("received datagram with context id {}", context_id);
                            break;
                        }
                    }
                }
            }

            stream.finish().await?;

            anyhow::Ok(())
        };

        let (req_res, drive_res) = tokio::join!(request, drive);
        if let Err(err) = req_res {
            match err.downcast::<StreamError>() {
                Ok(err) => {
                    if err.is_h3_no_error() {
                        info!("connection closed with H3_NO_ERROR");
                    } else {
                        error!("request failed: {:?}", err);
                    }
                }
                Err(err) => {
                    error!("request failed#2: {:?}", err);
                }
            }
        }
        if let Err(err) = drive_res? {
            if err.is_h3_no_error() {
                info!("connection closed with H3_NO_ERROR");
            } else {
                error!("connection closed with error: {:?}", err);
                return Err(err.into());
            }
        }

        info!("request finished");
        anyhow::Ok(())
    });

    let _ = tokio::join!(handle);
    Ok(())
}

pub async fn open_udp_proxy_server(server_addr: SocketAddr) -> anyhow::Result<()> {
    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    let alpn = [msquic::BufferRef::from("h3")];

    // create msquic-async listener
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(100_000)
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

        let cert = include_bytes!("cert.pem");
        let key = include_bytes!("key.pem");

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

        let cert = include_str!("cert.pem");
        let key = include_bytes!("key.pem");

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

        configuration
            .load_credential(&cred_config)
            .map_err(|status| {
                anyhow::anyhow!("Configuration::load_credential failed: {}", status)
            })?;
    };

    let listener = msquic_async::Listener::new(&registration, configuration)?;

    listener.start(&[msquic::BufferRef::from("h3")], Some(server_addr))?;
    let server_addr = listener.local_addr()?;

    info!("listening on {}", server_addr);

    // handle incoming connections and requests

    while let Ok(conn) = listener.accept().await {
        info!("new connection established");
        tokio::spawn(async move {
            let sessions: Arc<Mutex<HashMap<StreamId, Arc<UdpSocket>>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let mut h3_conn =
                h3::server::Connection::new(h3_msquic_async::Connection::new(conn)).await?;
            let mut datagram_reader = h3_conn.get_datagram_reader();
            let sessions_clone = sessions.clone();
            tokio::spawn(async move {
                loop {
                    let datagram = datagram_reader.read_datagram().await?;
                    info!("received datagram: {:?}", datagram);
                    let stream_id = datagram.stream_id();
                    let datagram = datagram.into_payload();
                    let (context_id, payload) = decode_var_int(datagram.chunk());
                    if context_id == 0 {
                        let socket = {
                            let guard = sessions_clone.lock().unwrap();
                            guard.get(&stream_id).expect("socket registered").clone()
                        };
                        if let Err(err) = socket.send(payload).await {
                            error!("failed to send datagram: {:?}", err);
                            continue;
                        }
                    } else {
                        info!("received datagram with context id {}", context_id);
                        break;
                    }
                }
                anyhow::Ok(())
            });

            loop {
                match h3_conn.accept().await? {
                    Some(req_resolver) => {
                        let (req, mut stream) = match req_resolver.resolve_request().await {
                            Ok(req) => req,
                            Err(err) => {
                                error!("error resolving request: {}", err);
                                continue;
                            }
                        };
                        info!("new request: {:#?}", req);

                        let mut datagram_sender = h3_conn.get_datagram_sender(stream.id());
                        let sessions_clone = sessions.clone();
                        tokio::spawn(async move{
                            let (resp, socket) = if validate_connect_udp(&req) {
                                match path_to_socketaddr(req.uri().path().as_bytes()) {
                                    Some(addr) => {
                                        info!("connect-udp to {}", addr);
                                        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                                        socket.connect(addr).await?;
                                        (
                                            http::Response::builder()
                                                .status(http::StatusCode::OK)
                                                .body(())?,
                                            Some(socket),
                                        )
                                    }
                                    None => {
                                        error!("invalid path");
                                        (
                                            http::Response::builder()
                                                .status(http::StatusCode::BAD_REQUEST)
                                                .body(())?,
                                            None,
                                        )
                                    }
                                }
                            } else {
                                (
                                    http::Response::builder()
                                        .status(http::StatusCode::BAD_REQUEST)
                                        .body(())?,
                                    None,
                                )
                            };

                            match stream.send_response(resp).await {
                                Ok(_) => {
                                    info!("successfully respond to connection");
                                }
                                Err(err) => {
                                    error!("unable to send response to connection peer: {:?}", err);
                                }
                            }

                            if let Some(socket) = socket {
                                {
                                    let mut guard = sessions_clone.lock().unwrap();
                                    guard.insert(stream.id(), socket.clone());
                                }
                                let mut buf = [0; 65535];
                                loop {
                                    let len = socket.recv(&mut buf).await?;
                                    let mut datagram = BytesMut::with_capacity(1 + len);
                                    datagram.put_u8(0); // 1 byte for datagram header
                                    datagram.put_slice(&buf[..len]);
                                    match datagram_sender.send_datagram(datagram.freeze()) {
                                        Ok(_) => {
                                            info!("sent datagram to stream {}", stream.id());
                                        }
                                        Err(err) => {
                                            error!("failed to send datagram: {:?}", err);
                                            continue;
                                        }
                                    }
                                }
                            }
                            anyhow::Ok(stream.finish().await?)
                        });
                    }

                    // indicating no more streams to be received
                    None => {
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    Ok(())
}


/**
 * RFC9298 specify connect-udp path should be a template like /.well-known/masque/udp/192.0.2.6/443/
 */
fn socketaddr_to_connect_udp_path(addr: &SocketAddr) -> String {
    let ip_string = addr.ip().to_string().replace(":", "%3A"); // encode ':' in IPv6 address in URI
    format!("/.well_known/masque/udp/{}/{}/", ip_string, addr.port())
}

/**
 * Parse pseudo-header path for CONNECT UDP to SocketAddr
 */
fn path_to_socketaddr(path: &[u8]) -> Option<SocketAddr> {
    // for now, let's assume path pattern is "/something.../target-host/target-port/"
    let mut split_iter = std::io::BufRead::split(path, b'/');
    let mut second_last = None;
    let mut last = None;
    while let Some(curr) = split_iter.next() {
        if let Ok(curr) = curr {
            second_last = last;
            last = Some(curr);
        } else {
            return None;
        }
    }
    if second_last.is_some() && last.is_some() {
        let second_last = second_last.unwrap();
        let last = last.unwrap();
        let second_last = std::str::from_utf8(&second_last);
        let last = std::str::from_utf8(&last);
        if second_last.is_ok() && last.is_ok() {
            let url_str = format!("scheme://{}:{}/", second_last.unwrap(), last.unwrap());
            let url = url::Url::parse(&url_str);
            if let Ok(url) = url {
                let socket_addrs = url.to_socket_addrs();
                if let Ok(mut socket_addrs) = socket_addrs {
                    return socket_addrs.next();
                }
            }
        }
    }

    None
}

fn decode_var_int(data: &[u8]) -> (u64, &[u8]) {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v = v & 0x3f;
    for i in 1..length - 1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    (v, &data[length..])
}

fn validate_connect_udp(request: &http::request::Request<()>) -> bool {
    let protocol = request.extensions().get::<Protocol>();
    matches!((request.method(), protocol), (&http::Method::CONNECT, Some(p)) if p == &Protocol::CONNECT_UDP)
}
