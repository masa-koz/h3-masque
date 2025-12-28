use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::stream::{self, StreamExt};
use futures_concurrency::prelude::*;
use futures_concurrency::stream::StreamGroup;
use h3::{client::RequestStream as ClientRequestStream, quic::BidiStream};
use h3::{
    error::{ConnectionError, StreamError},
    ext::Protocol,
};
use h3_datagram::{datagram::Datagram, datagram_handler::HandleDatagramsExt};
use h3_msquic_async::{msquic, msquic_async};
use std::collections::HashMap;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub async fn connect_udp_proxy(
    registration: &msquic::Registration,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(local_addr).await?;
    let local_addr = socket.local_addr()?;
    info!("local address: {}", local_addr);

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

        let datagram_reader = driver.get_datagram_reader();
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
                    crate::socketaddr_to_connect_udp_path(&Some(remote_addr))
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
            enum Event {
                UdpRecv(Bytes, SocketAddr),
                DatagramRecv(Datagram<Bytes>),
            }
            let udp_recv = Box::pin(stream::unfold((), |_| async {
                let mut buf = [0; 65535];
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => Some((
                        Event::UdpRecv(Bytes::copy_from_slice(&buf[..len]), addr),
                        (),
                    )),
                    Err(_) => None,
                }
            }));
            let datagram_read = Box::pin(stream::unfold(
                datagram_reader,
                |mut datagram_reader| async move {
                    match datagram_reader.read_datagram().await {
                        Ok(datagram) => Some((Event::DatagramRecv(datagram), datagram_reader)),
                        Err(_) => None,
                    }
                },
            ));
            let mut event_stream = udp_recv.merge(datagram_read);
            while let Some(event) = event_stream.next().await {
                match event {
                    Event::UdpRecv(data, addr) => {
                        info!("received datagram from {}: {:?}", addr, data);
                        client_addr = Some(addr);
                        let mut datagram = BytesMut::with_capacity(1 + data.len());
                        datagram.put_u8(0); // 1 byte for datagram header
                        datagram.put_slice(&data);
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
                    Event::DatagramRecv(datagram) => {
                        info!("received datagram: {:?}", datagram);
                        let datagram = datagram.into_payload();
                        if let Some((context_id, payload)) = crate::decode_var_int(datagram.chunk())
                        {
                            if context_id == 0 {
                                if let Err(err) = socket
                                    .send_to(
                                        payload,
                                        client_addr.as_ref().map(|a| a.clone()).unwrap(),
                                    )
                                    .await
                                {
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

struct ClientContextInfo {
    uncompressed_context_id: Option<u64>,
    id_to_addr_map: HashMap<u64, Option<SocketAddr>>,
    addr_to_id_map: HashMap<SocketAddr, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundProxyEvent {
    NotifyPublicAddress(SocketAddr),
    NotifyObservedAddress {
        local_address: SocketAddr,
        observed_address: SocketAddr,
    },
}

pub async fn connect_udp_bind_proxy(
    registration: &msquic::Registration,
    local_bind_addr: SocketAddr,
    server_addr: SocketAddr,
    target_addr: Option<SocketAddr>,
) -> anyhow::Result<(
    JoinHandle<anyhow::Result<()>>,
    mpsc::Receiver<BoundProxyEvent>,
)> {
    let alpn = [msquic::BufferRef::from("h3")];
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
    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;

    let conn = msquic_async::Connection::new(&registration)?;
    conn.set_share_binding(true)?;
    conn.start(
        &configuration,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await?;

    let (event_sender, event_receiver) = mpsc::channel(1);

    let event_handle = {
        let conn = conn.clone();
        let event_sender = event_sender.clone();
        tokio::task::spawn(async move {
            while let Ok(event) = poll_fn(|cx| conn.poll_event(cx)).await {
                match event {
                    msquic_async::ConnectionEvent::NotifyObservedAddress {
                        local_address,
                        observed_address,
                    } => {
                        if let Err(err) = event_sender
                            .send(BoundProxyEvent::NotifyObservedAddress {
                                local_address,
                                observed_address,
                            })
                            .await
                        {
                            error!("failed to send NotifyObservedAddress event: {:?}", err);
                        }
                    }
                    msquic_async::ConnectionEvent::NotifyRemoteAddressAdded {
                        address,
                        sequence_number,
                    } => {
                        info!(
                            "remote address added address: {}, sequence number: {}",
                            address, sequence_number
                        );
                    }
                    msquic_async::ConnectionEvent::PathValidated {
                        local_address,
                        remote_address,
                    } => {
                        info!(
                            "path validated local address: {}, remote address: {}",
                            local_address, remote_address
                        );
                    }
                    msquic_async::ConnectionEvent::NotifyRemoteAddressRemoved {
                        sequence_number,
                    } => {
                        info!(
                            "remote address removed with sequence number: {}",
                            sequence_number
                        );
                    }
                }
            }
        })
    };
    let handle = tokio::spawn(async move {
        let h3_conn = h3_msquic_async::Connection::new(conn);

        let context_id = 2u64; // start from 2, as 0 is normal udp connect
        let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

        let datagram_reader = driver.get_datagram_reader();
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
                    crate::socketaddr_to_connect_udp_path(&target_addr)
                ))
                .header("connect-udp-bind", "?1")
                .header("capsule-protocol", "?1")
                .header("authorization", "dummy-authorization")
                .extension(Protocol::CONNECT_UDP)
                .body(())?;

            // sending request results in a bidirectional stream,
            // which is also used for receiving response
            let mut stream = send_request.send_request(req).await?;
            let stream_id = stream.id();
            info!("request sent, stream id: {}", stream_id);

            info!("receiving response ...");

            let resp = stream.recv_response().await?;

            info!("response: {:?} {}", resp.version(), resp.status());
            info!("headers: {:#?}", resp.headers());
            let public_addrs = resp
                .headers()
                .get("proxy-public-address")
                .and_then(|value| value.to_str().ok())
                .and_then(|s| {
                    Some(
                        s.split(',')
                            .filter_map(|v| v.parse::<SocketAddr>().ok())
                            .collect::<Vec<_>>(),
                    )
                })
                .ok_or_else(|| anyhow::anyhow!("invalid proxy-public-address header value"))?;
            if public_addrs.is_empty() {
                bail!("no public address provided by server");
            }
            for addr in public_addrs.into_iter() {
                if let Err(err) = event_sender
                    .send(BoundProxyEvent::NotifyPublicAddress(addr))
                    .await
                {
                    error!("failed to send NotifyPublicAddress event: {:?}", err);
                }
            }

            let mut req_buf = BytesMut::new();
            let req_length =
                crate::encode_var_int(0x11).len() + 1 + crate::encode_var_int(context_id).len() + 1;
            req_buf.extend_from_slice(
                &crate::encode_var_int(0x11), // COMPRESSION capsule
            );
            req_buf.extend_from_slice(&crate::encode_var_int(req_length as u64));
            req_buf.extend_from_slice(&crate::encode_var_int(context_id));
            req_buf.put_u8(0); // IP version 0 (no address)
            stream.send_data(req_buf.freeze()).await.unwrap();

            let (resp_capsule_type, resp_context_id, _resp_buf) =
                recv_capsule_response(&mut stream, BytesMut::new()).await?;
            if resp_capsule_type != 0x12 {
                bail!(
                    "expected COMPRESSION_ASSIGN_ACK capsule, got {}",
                    resp_capsule_type
                );
            }
            if resp_context_id != context_id {
                bail!(
                    "expected context id {}, got {}",
                    context_id,
                    resp_context_id
                );
            }

            let mut context_info = ClientContextInfo {
                uncompressed_context_id: Some(context_id),
                id_to_addr_map: HashMap::new(),
                addr_to_id_map: HashMap::new(),
            };
            context_info.id_to_addr_map.insert(context_id, None);

            let mut sessions: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();

            stream_id_sender.send(stream_id).await?;
            let mut datagram_sender = datagram_tx_receiver.recv().await.unwrap();

            enum Event {
                UdpRecv(Bytes, SocketAddr),
                DatagramRecv(Datagram<Bytes>),
            }

            let mut datagram_read = Box::pin(stream::unfold(
                datagram_reader,
                |mut datagram_reader| async move {
                    match datagram_reader.read_datagram().await {
                        Ok(datagram) => Some((Event::DatagramRecv(datagram), datagram_reader)),
                        Err(_) => None,
                    }
                },
            ));

            let mut udp_recv_group = StreamGroup::new();
            loop {
                tokio::select! {
                    Some(Event::UdpRecv(data, remote_addr)) = udp_recv_group.next() => {
                        info!("received datagram to {}", remote_addr);
                        let (context_id, compressed) =
                            if let Some(id) = context_info.addr_to_id_map.get(&remote_addr) {
                                (*id, true)
                            } else {
                                if let Some(id) = context_info.uncompressed_context_id {
                                    (id, false)
                                } else {
                                    error!("no uncompressed context id available");
                                    continue;
                                }
                            };
                        let mut datagram = BytesMut::new();
                        datagram.extend_from_slice(&crate::encode_var_int(context_id));
                        if !compressed {
                            match remote_addr.ip() {
                                std::net::IpAddr::V4(ipv4) => {
                                    datagram.put_u8(4); // IP version
                                    datagram.extend_from_slice(&ipv4.octets());
                                }
                                std::net::IpAddr::V6(ipv6) => {
                                    datagram.put_u8(6); // IP version
                                    datagram.extend_from_slice(&ipv6.octets());
                                }
                            }
                            datagram.extend_from_slice(&remote_addr.port().to_be_bytes());
                        }
                        datagram.extend_from_slice(&data);
                        match datagram_sender.send_datagram(datagram.freeze()) {
                            Ok(_) => {
                                info!("sent datagram to stream {}", stream_id);
                            }
                            Err(err) => {
                                error!("failed to send datagram: {:?}", err);
                                continue;
                            }
                        }
                    }
                    Some(Event::DatagramRecv(datagram)) = datagram_read.next() => {
                        info!("received datagram");
                        let datagram = datagram.into_payload();
                        if let Some((context_id, mut payload)) = crate::decode_var_int(datagram.chunk()) {
                            let remote_addr = match context_info.id_to_addr_map.get(&context_id) {
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
                                            let port =
                                                u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                            let addr =
                                                SocketAddr::new(std::net::IpAddr::V4(ip), port);
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
                                            let port =
                                                u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                            let addr =
                                                SocketAddr::new(std::net::IpAddr::V6(ip), port);
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

                            if !sessions.contains_key(&remote_addr) {
                                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                                socket.connect(local_bind_addr).await?;
                                sessions.insert(remote_addr.clone(), socket.clone());

                                let udp_recv = Box::pin(stream::unfold(
                                    (socket, remote_addr),
                                    |(socket, remote_addr)| async move {
                                        let mut buf = [0; 65535];
                                        match socket.recv(&mut buf).await {
                                            Ok(len) => Some((
                                                Event::UdpRecv(
                                                    Bytes::copy_from_slice(&buf[..len]),
                                                    remote_addr.clone(),
                                                ),
                                                (socket, remote_addr),
                                            )),
                                            Err(_) => None,
                                        }
                                    },
                                ));
                                udp_recv_group.insert(udp_recv);
                            }
                            let socket = sessions.get(&remote_addr).unwrap();
                            if let Err(err) = socket.send(payload).await {
                                error!("failed to send datagram: {:?}", err);
                            }
                        } else {
                            error!("failed to decode var int from datagram");
                            continue;
                        }
                    }
                }
            }
            #[allow(unreachable_code)]
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
        event_handle.await?;

        info!("request finished");
        anyhow::Ok(())
    });
    Ok((handle, event_receiver))
}

async fn recv_capsule_response<T>(
    stream: &mut ClientRequestStream<T, Bytes>,
    mut buf: BytesMut,
) -> anyhow::Result<(u64, u64, BytesMut)>
where
    T: BidiStream<Bytes> + 'static + Send,
{
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
                    0x12 | 0x13 => {
                        // COMPRESSION_ASSIGN_ACK / COMPRESSION_CLOSE capsule
                        let Some((context_id, _payload)) = crate::decode_var_int(payload) else {
                            bail!("invalid COMPRESSION_ASSIGN ACK capsule");
                        };
                        buf.advance(length as usize);
                        return Ok((capsule_type, context_id, buf));
                    }
                    _ => {
                        bail!("unknown capsule type {}", capsule_type);
                    }
                }
            }
            None => {
                bail!("stream closed");
            }
        }
    }
}
