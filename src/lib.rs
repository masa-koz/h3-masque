use bytes::{BufMut, BytesMut};
use h3::{
    error::{ConnectionError, StreamError},
    ext::Protocol,
};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_msquic_async::{msquic, msquic_async};
use std::future::poll_fn;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info};

pub async fn open_udp_proxy(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    let alpn = [msquic::BufferRef::from("h3")];
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
    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;

    let handle = tokio::spawn(async move {
        let socket = UdpSocket::bind(local_addr).await?;

        let conn = msquic_async::Connection::new(&registration)?;
        conn.start(
            &configuration,
            &server_addr.ip().to_string(),
            server_addr.port(),
        )
        .await?;

        let h3_conn = h3_msquic_async::Connection::new(conn);

        let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

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
            // finish on the sending side
            // stream.finish().await?;

            info!("receiving response ...");

            let resp = stream.recv_response().await?;

            info!("response: {:?} {}", resp.version(), resp.status());
            info!("headers: {:#?}", resp.headers());

            stream_id_sender.send(stream.id()).await?;
            if let Some(mut datagram_sender) = datagram_tx_receiver.recv().await {
                let mut buf = BytesMut::with_capacity(1024);
                buf.put(&b"\x00hello world"[..]);
                datagram_sender.send_datagram(buf.freeze())?;
            }

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

        anyhow::Ok(())
    });

    let _ = tokio::join!(handle);
    Ok(())
}

/**
 * RFC9298 specify connect-udp path should be a template like /.well-known/masque/udp/192.0.2.6/443/
 */
fn socketaddr_to_connect_udp_path(addr: &SocketAddr) -> String {
    let ip_string = addr.ip().to_string().replace(":", "%3A"); // encode ':' in IPv6 address in URI
    format!("/.well_known/masque/udp/{}/{}/", ip_string, addr.port())
}
