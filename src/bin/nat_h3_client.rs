/// This file is based on the `client.rs` example from the `h3` crate.
use argh::FromArgs;
use futures::future;
use h3::error::{ConnectionError, StreamError};
use h3_msquic_async::msquic;
use h3_msquic_async::msquic_async;
use std::env;
use std::fs::OpenOptions;
use std::future::poll_fn;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

#[derive(FromArgs, Clone)]
/// client args
struct CmdOptions {
    /// target server address
    #[argh(option, default = "String::from(\"127.0.0.1:4443\")")]
    target: String,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd_opts: CmdOptions = argh::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;

    let alpn = [msquic::BufferRef::from("h3")];
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
        ),
    )?;
    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;

    let conn = msquic_async::Connection::new(&registration)?;
    if let Ok(sslkeylogfile) = env::var("SSLKEYLOGFILE") {
        info!("SSLKEYLOGFILE is set: {}", sslkeylogfile);
        conn.set_sslkeylog_file(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(sslkeylogfile)?,
        )?;
    }
    conn.set_share_binding(true)?;
    let target = cmd_opts
        .target
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("failed to parse target address: {}", e))?;
    conn.start(&configuration, &target.ip().to_string(), target.port()).await?;

    let local_addr = conn.get_local_addr()?;
    info!("connected from {} to {}", local_addr, target);

    let event_handle = {
        let conn = conn.clone();
        tokio::task::spawn(async move {
            while let Ok(event) = poll_fn(|cx| conn.poll_event(cx)).await {
                match event {
                    msquic_async::ConnectionEvent::NotifyObservedAddress { local_address, observed_address } => {
                        info!("local address: {}, observed address: {}", local_address, observed_address);
                        conn.add_local_addr(local_address.clone(), local_address)?;
                    }
                    msquic_async::ConnectionEvent::NotifyRemoteAddressAdded { address, sequence_number } => {
                        info!("Added remote address: {}, sequence number: {}", address, sequence_number);
                    }
                    msquic_async::ConnectionEvent::PathValidated { local_address, remote_address } => {
                        info!("path validated local address: {}, remote address: {}", local_address, remote_address);
                    }
                    msquic_async::ConnectionEvent::NotifyRemoteAddressRemoved { sequence_number } => {
                        info!("Removed remote address with sequence number: {}", sequence_number);
                    }
                }
            }
            anyhow::Ok(())
        })
    };
    let h3_conn = h3_msquic_async::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    let drive = async move {
        Err::<(), ConnectionError>(future::poll_fn(|cx| driver.poll_close(cx)).await)
    };
    let request = async move {
        info!("sending request ...");

        let req = http::Request::builder()
            .uri("https://127.0.0.1:8443/")
            .header("x-advertise-address", format!("{}", local_addr))
            .body(())?;

        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = send_request.send_request(req).await?;

        // finish on the sending side
        stream.finish().await?;

        info!("receiving response ...");

        let resp = stream.recv_response().await?;

        info!("response: {:?} {}", resp.version(), resp.status());
        info!("headers: {:#?}", resp.headers());

        // `recv_data()` must be called after `recv_response()` for
        // receiving potential response body
        while let Some(mut chunk) = stream.recv_data().await? {
            let mut out = tokio::io::stdout();
            out.write_all_buf(&mut chunk).await?;
            out.flush().await?;
        }

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        Ok::<_, anyhow::Error>(())
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
                error!("request failed: {:?}", err);
            }
        }
    }
    if let Err(err) = drive_res {
        if err.is_h3_no_error() {
            info!("connection closed with H3_NO_ERROR");
        } else {
            error!("connection closed with error: {:?}", err);
            return Err(err.into());
        }
    }

    event_handle.await??;
    Ok(())
}
