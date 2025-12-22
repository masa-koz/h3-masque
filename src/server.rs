use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::proto::stream::StreamId;
use h3::{quic::BidiStream, server::RequestStream};
use h3_datagram::{
    datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt},
    quic_traits::{RecvDatagram, SendDatagram},
};
use h3_msquic_async::{msquic, msquic_async};
use http::Request;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub async fn serve_udp_proxy(
    registration: &msquic::Registration,
    server_addr: SocketAddr,
) -> anyhow::Result<()> {
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
                    if let Some((context_id, payload)) = crate::decode_var_int(datagram.chunk()) {
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
                    } else {
                        error!("failed to decode var int from datagram");
                        continue;
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
                        tokio::spawn(async move {
                            let (resp, socket) = if crate::validate_connect_udp(&req) {
                                match crate::path_to_socketaddr(req.uri().path().as_bytes()) {
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

struct ContextInfo {
    uncompressed_context_id: Option<u64>,
    compressions: HashMap<SocketAddr, u64>,
}

pub async fn serve_udp_bind_proxy(
    registration: &msquic::Registration,
    server_addr: SocketAddr,
) -> anyhow::Result<()> {
    let alpn = [msquic::BufferRef::from("h3")];

    // create msquic-async listener
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(100_000)
                .set_KeepAliveIntervalMs(1000)
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
            let sessions: Arc<
                Mutex<HashMap<StreamId, (Arc<UdpSocket>, HashMap<u64, Option<SocketAddr>>)>>,
            > = Arc::new(Mutex::new(HashMap::new()));
            let mut h3_conn =
                h3::server::Connection::new(h3_msquic_async::Connection::new(conn)).await?;

            let _handle_datagram =
                run_server_process_datagram(h3_conn.get_datagram_reader(), sessions.clone());
            loop {
                match h3_conn.accept().await? {
                    Some(req_resolver) => {
                        let (req, stream) = match req_resolver.resolve_request().await {
                            Ok(req) => req,
                            Err(err) => {
                                error!("error resolving request: {}", err);
                                continue;
                            }
                        };
                        info!("new request: {:#?}", req);

                        let stream_id = stream.id();
                        let _handle_request = run_server_process_request(
                            stream,
                            h3_conn.get_datagram_sender(stream_id),
                            sessions.clone(),
                            req,
                        );
                    }
                    // indicating no more streams to be received
                    None => {
                        break;
                    }
                }
            }
            anyhow::Ok(())
        });
    }
    Ok(())
}

fn run_server_process_datagram<H>(
    mut datagram_reader: DatagramReader<H>,
    sessions: Arc<Mutex<HashMap<StreamId, (Arc<UdpSocket>, HashMap<u64, Option<SocketAddr>>)>>>,
) -> JoinHandle<anyhow::Result<()>>
where
    H: RecvDatagram + 'static + Send,
    <H as RecvDatagram>::Buffer: Send,
{
    tokio::spawn(async move {
        loop {
            let datagram = datagram_reader.read_datagram().await?;
            let stream_id = datagram.stream_id();
            let datagram = datagram.into_payload();
            if let Some((context_id, mut payload)) = crate::decode_var_int(datagram.chunk()) {
                let (socket, addr) = {
                    let guard = sessions.lock().unwrap();
                    let (socket, contexts) = guard.get(&stream_id).expect("socket registered");
                    let addr = match contexts.get(&context_id) {
                        Some(Some(addr)) => addr.clone(),
                        Some(None) => {
                            if payload.len() < 1 {
                                error!(
                                    "missing IP version byte in datagram with context id {}",
                                    context_id
                                );
                                continue;
                            }
                            let ip_version = payload.get_u8();
                            match ip_version {
                                4 => {
                                    if payload.len() < 6 {
                                        error!(
                                            "missing IPv4 address and port in datagram with context id {}",
                                            context_id
                                        );
                                        continue;
                                    }
                                    let ip_bytes = &payload[..4];
                                    let port_bytes = &payload[4..6];
                                    let ip = std::net::Ipv4Addr::new(
                                        ip_bytes[0],
                                        ip_bytes[1],
                                        ip_bytes[2],
                                        ip_bytes[3],
                                    );
                                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                                    info!("context id {} target {}", context_id, addr);
                                    payload.advance(6);
                                    addr
                                }
                                6 => {
                                    if payload.len() < 18 {
                                        error!(
                                            "missing IPv6 address and port in datagram with context id {}",
                                            context_id
                                        );
                                        continue;
                                    }
                                    let ip_bytes = &payload[..16];
                                    let port_bytes = &payload[16..18];
                                    let ip = std::net::Ipv6Addr::from([
                                        ip_bytes[0],
                                        ip_bytes[1],
                                        ip_bytes[2],
                                        ip_bytes[3],
                                        ip_bytes[4],
                                        ip_bytes[5],
                                        ip_bytes[6],
                                        ip_bytes[7],
                                        ip_bytes[8],
                                        ip_bytes[9],
                                        ip_bytes[10],
                                        ip_bytes[11],
                                        ip_bytes[12],
                                        ip_bytes[13],
                                        ip_bytes[14],
                                        ip_bytes[15],
                                    ]);
                                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                    let addr = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                                    info!("context id {} target {}", context_id, addr);
                                    payload.advance(18);
                                    addr
                                }
                                _ => {
                                    error!(
                                        "unknown IP version {} in datagram with context id {}",
                                        ip_version, context_id
                                    );
                                    continue;
                                }
                            }
                        }
                        None => {
                            error!("unknown context id {}", context_id);
                            continue;
                        }
                    };
                    (socket.clone(), addr)
                };
                if let Err(err) = socket.send_to(payload, addr).await {
                    error!("failed to send datagram: {:?}", err);
                    continue;
                }
            } else {
                error!("failed to decode var int from datagram");
                continue;
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    })
}

fn run_server_process_request<T, H>(
    mut stream: RequestStream<T, Bytes>,
    datagram_sender: DatagramSender<H, Bytes>,
    sessions: Arc<Mutex<HashMap<StreamId, (Arc<UdpSocket>, HashMap<u64, Option<SocketAddr>>)>>>,
    req: Request<()>,
) -> JoinHandle<anyhow::Result<()>>
where
    T: BidiStream<Bytes> + 'static + Send,
    H: SendDatagram<Bytes> + 'static + Send,
{
    tokio::spawn(async move {
        let (resp, socket) = if crate::validate_connect_udp(&req) {
            match (
                req.headers().get("connect-udp-bind"),
                req.headers().get("capsule-protocol"),
            ) {
                (Some(v1), Some(v2)) => {
                    info!("connect-udp-bind {:?} and capsule-protocol {:?}", v1, v2);
                    if v1 == "?1" && v2 == "?1" {
                        let socket = match crate::path_to_socketaddr(req.uri().path().as_bytes()) {
                            Some(addr) => {
                                info!("connect-udp to {}", addr);
                                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                                socket.connect(addr).await?;
                                socket
                            }
                            None => Arc::new(UdpSocket::bind("0.0.0.0:0").await?),
                        };
                        (
                            http::Response::builder()
                                .status(http::StatusCode::OK)
                                .header("connect-udp-bind", "?1")
                                .header("capsule-protocol", "?1")
                                .header(
                                    "proxy-public-address",
                                    format!("{}", socket.local_addr().unwrap()),
                                )
                                .body(())?,
                            Some(socket),
                        )
                    } else {
                        (
                            http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(())?,
                            None,
                        )
                    }
                }
                (_, _) => (
                    http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(())?,
                    None,
                ),
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

        if socket.is_none() {
            return anyhow::Ok(stream.finish().await?);
        }
        let socket = socket.unwrap();
        {
            let mut guard = sessions.lock().unwrap();
            guard.insert(stream.id(), (socket.clone(), HashMap::new()));
        }

        let context_info: Arc<Mutex<ContextInfo>> = Arc::new(Mutex::new(ContextInfo {
            uncompressed_context_id: None,
            compressions: HashMap::new(),
        }));
        let stream_id = stream.id();
        let handle_capsule =
            run_server_process_capsule(stream, sessions, context_info.clone(), stream_id.clone());
        let handle_udp = run_server_process_udp(socket, datagram_sender, context_info, stream_id);
        let _ = tokio::join!(handle_capsule, handle_udp);
        anyhow::Ok(())
    })
}

fn run_server_process_capsule<T>(
    mut stream: RequestStream<T, Bytes>,
    sessions: Arc<Mutex<HashMap<StreamId, (Arc<UdpSocket>, HashMap<u64, Option<SocketAddr>>)>>>,
    context_info: Arc<Mutex<ContextInfo>>,
    stream_id: StreamId,
) -> JoinHandle<anyhow::Result<()>>
where
    T: BidiStream<Bytes> + 'static + Send,
{
    tokio::task::spawn(async move {
        let mut buf = BytesMut::new();
        loop {
            match stream.recv_data().await? {
                Some(data) => {
                    buf.extend_from_slice(data.chunk());
                    let Some((capsule_type, payload)) = crate::decode_var_int(buf.chunk()) else {
                        // incomplete capsule
                        continue;
                    };
                    let Some((length, payload)) = crate::decode_var_int(payload) else {
                        // incomplete capsule
                        continue;
                    };
                    if buf.len() < length as usize {
                        // incomplete capsule
                        continue;
                    }
                    match capsule_type {
                        0x11 => {
                            // COMPRESSION_ASSIGN capsule
                            let Some((context_id, mut payload)) = crate::decode_var_int(payload)
                            else {
                                buf.advance(length as usize);
                                continue;
                            };
                            if payload.len() < 1 {
                                buf.advance(length as usize);
                                continue;
                            }
                            let ip_version = payload.get_u8();
                            let addr = match ip_version {
                                0 => {
                                    info!(
                                        "received COMPRESSION_ASSIGN capsule with context id {}",
                                        context_id
                                    );
                                    None
                                }
                                4 => {
                                    if payload.len() < 6 {
                                        error!(
                                            "missing IPv4 address and port in COMPRESSION_ASSIGN capsule: context id {}",
                                            context_id
                                        );
                                        buf.advance((length) as usize);
                                        continue;
                                    }
                                    let ip_bytes = &payload[..4];
                                    let port_bytes = &payload[4..6];
                                    let ip = std::net::Ipv4Addr::new(
                                        ip_bytes[0],
                                        ip_bytes[1],
                                        ip_bytes[2],
                                        ip_bytes[3],
                                    );
                                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                                    Some(addr)
                                }
                                6 => {
                                    if payload.len() < 18 {
                                        error!(
                                            "missing IPv6 address and port in COMPRESSION_ASSIGN capsule: context id {}",
                                            context_id
                                        );
                                        buf.advance((length) as usize);
                                        continue;
                                    }
                                    let ip_bytes = &payload[..16];
                                    let port_bytes = &payload[16..18];
                                    let ip = std::net::Ipv6Addr::from([
                                        ip_bytes[0],
                                        ip_bytes[1],
                                        ip_bytes[2],
                                        ip_bytes[3],
                                        ip_bytes[4],
                                        ip_bytes[5],
                                        ip_bytes[6],
                                        ip_bytes[7],
                                        ip_bytes[8],
                                        ip_bytes[9],
                                        ip_bytes[10],
                                        ip_bytes[11],
                                        ip_bytes[12],
                                        ip_bytes[13],
                                        ip_bytes[14],
                                        ip_bytes[15],
                                    ]);
                                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                    let addr = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                                    Some(addr)
                                }
                                _ => {
                                    error!(
                                        "unknown IP version in COMPRESSION_ASSIGN capsule: {}",
                                        ip_version
                                    );
                                    buf.advance((length) as usize);
                                    continue;
                                }
                            };
                            buf.advance((length) as usize);

                            {
                                let mut guard = sessions.lock().unwrap();
                                let Some((_, contexts)) = guard.get_mut(&stream_id) else {
                                    unreachable!("socket registered");
                                };
                                contexts.insert(context_id, addr.clone());
                            }
                            {
                                let mut guard = context_info.lock().unwrap();
                                if let Some(addr) = addr {
                                    guard.compressions.insert(addr, context_id);
                                } else {
                                    guard.uncompressed_context_id = Some(context_id);
                                }
                            }

                            let mut resp_buf = BytesMut::new();
                            let resp_length = crate::encode_var_int(0x12).len()
                                + 1
                                + crate::encode_var_int(context_id).len();
                            resp_buf.extend_from_slice(
                                &crate::encode_var_int(0x12), // COMPRESSION_ACK capsule
                            );
                            resp_buf.extend_from_slice(&crate::encode_var_int(resp_length as u64));
                            resp_buf.extend_from_slice(&crate::encode_var_int(context_id));
                            stream.send_data(resp_buf.freeze()).await.unwrap();
                        }
                        _ => {
                            error!("unknown capsule type {}", capsule_type);
                            buf.advance(length as usize);
                            continue;
                        }
                    }
                }
                None => break,
            }
        }
        anyhow::Ok(())
    })
}

fn run_server_process_udp<H>(
    socket: Arc<UdpSocket>,
    mut datagram_sender: DatagramSender<H, Bytes>,
    context_info: Arc<Mutex<ContextInfo>>,
    stream_id: StreamId,
) -> JoinHandle<anyhow::Result<()>>
where
    H: SendDatagram<Bytes> + 'static + Send,
{
    tokio::task::spawn(async move {
        loop {
            let mut buf = [0u8; 65535];
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = &buf[..len];
                    let (context_id, compressed) = {
                        let guard = context_info.lock().unwrap();
                        match guard.compressions.get(&addr) {
                            Some(id) => (*id, true),
                            None => match guard.uncompressed_context_id {
                                Some(id) => (id, false),
                                None => {
                                    error!("no context id for uncompressed");
                                    continue;
                                }
                            },
                        }
                    };
                    let mut datagram = BytesMut::new();
                    datagram.extend_from_slice(&crate::encode_var_int(context_id));
                    if !compressed {
                        match addr.ip() {
                            std::net::IpAddr::V4(ipv4) => {
                                datagram.put_u8(4); // IP version
                                datagram.extend_from_slice(&ipv4.octets());
                            }
                            std::net::IpAddr::V6(ipv6) => {
                                datagram.put_u8(6); // IP version
                                datagram.extend_from_slice(&ipv6.octets());
                            }
                        }
                        datagram.extend_from_slice(&addr.port().to_be_bytes());
                    }
                    datagram.extend_from_slice(data);
                    match datagram_sender.send_datagram(datagram.freeze()) {
                        Ok(_) => {
                            info!("sent datagram to stream {}", stream_id);
                        }
                        Err(err) => {
                            error!("failed to send datagram: {:?}", err);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        anyhow::Ok(())
    })
}
