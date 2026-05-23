use crate::core::circuit::Circuit;
use crate::core::metrics::{ClientMetrics, EventKind};
use anyhow::{Context, Result};
use common::MessageCommand;
use common::metrics::Direction;
use simple_socks5::conn::reply::Rep;
use simple_socks5::parse::AddrPort;
use simple_socks5::{ATYP, Socks5};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

const SOCKS5_READ_BUF_SIZE: usize = 4096;
const CONNECTED_TIMEOUT: Duration = Duration::from_secs(30);

/// Bridge a SOCKS5 client connection to a destination through the onion circuit.
pub async fn handle_stream(
    circuit: Arc<Mutex<Circuit>>,
    socks_stream: &mut TcpStream,
    destination: String,
    metrics: Arc<ClientMetrics>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let stream_id = {
        let mut c = circuit.lock().await;
        let id = c.allocate_stream_id();
        c.register_stream(id, tx);
        id
    };

    let circuit_id = circuit.lock().await.circuit_id;
    info!(
        "Opening stream {} on circuit {} to {}",
        stream_id, circuit_id, destination
    );

    let begin_payload = format!("{destination}\0").into_bytes();
    {
        let mut c = circuit.lock().await;
        c.send_message(stream_id, MessageCommand::Begin, &begin_payload)
            .await
            .context("Failed to send BEGIN message")?;
    }
    debug!("Sent BEGIN for stream {} to {}", stream_id, destination);

    metrics.push_event(EventKind::StreamBegin {
        circuit_id,
        stream_id,
        destination: destination.clone(),
    });

    let connected_msg = match tokio::time::timeout(CONNECTED_TIMEOUT, rx.recv()).await {
        Ok(Some(msg)) => msg,
        Ok(None) => {
            cleanup_stream(&circuit, socks_stream, stream_id).await;
            return Err(anyhow::anyhow!(
                "Circuit closed before CONNECTED received for stream {}",
                stream_id
            ));
        }
        Err(_) => {
            cleanup_stream(&circuit, socks_stream, stream_id).await;
            return Err(anyhow::anyhow!(
                "Timed out waiting for CONNECTED on stream {} ({}s)",
                stream_id,
                CONNECTED_TIMEOUT.as_secs()
            ));
        }
    };

    if connected_msg.command != MessageCommand::Connected {
        let _ = Socks5::send_conn_reply(
            socks_stream,
            Rep::GeneralFailure,
            ATYP::V4,
            AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
        )
        .await;
        cleanup_stream(&circuit, socks_stream, stream_id).await;
        return Err(anyhow::anyhow!(
            "Expected CONNECTED for stream {}, got {}",
            stream_id,
            connected_msg.command
        ));
    }

    info!(
        "Stream {} connected to {} on circuit {}",
        stream_id, destination, circuit_id
    );

    metrics.push_event(EventKind::StreamConnected {
        circuit_id,
        stream_id,
    });

    Socks5::send_conn_reply(
        socks_stream,
        Rep::Succeeded,
        ATYP::V4,
        AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
    )
    .await
    .context("Failed to send SOCKS5 success reply")?;

    let mut buf = [0u8; SOCKS5_READ_BUF_SIZE];

    loop {
        tokio::select! {
            result = socks_stream.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        debug!("SOCKS5 client closed stream {}", stream_id);
                        break;
                    }
                    Ok(n) => {
                        let data = buf.get(..n)
                            .ok_or_else(|| anyhow::anyhow!("Buffer read out of range"))?;

                        let mut send_failed = false;
                        for chunk in data.chunks(common::MAX_PAYLOAD_SIZE) {
                            let mut c = circuit.lock().await;
                            if let Err(e) = c.send_message(stream_id, MessageCommand::Data, chunk).await {
                                error!("Failed to send DATA on stream {}: {}", stream_id, e);
                                send_failed = true;
                                break;
                            }
                        }
                        if send_failed {
                            break;
                        }
                        metrics.bytes_sent.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        metrics.push_event(EventKind::StreamData {
                            circuit_id,
                            stream_id,
                            bytes: n,
                            direction: Direction::Forward,
                        });
                    }
                    Err(e) => {
                        warn!("Error reading from SOCKS5 client on stream {}: {}", stream_id, e);
                        break;
                    }
                }
            }

            msg = rx.recv() => {
                match msg {
                    Some(m) if m.command == MessageCommand::Data => {
                        if let Err(e) = socks_stream.write_all(&m.data).await {
                            warn!("Error writing to SOCKS5 client on stream {}: {}", stream_id, e);
                            break;
                        }
                    }
                    Some(m) if m.command == MessageCommand::End => {
                        debug!("Received END for stream {} from exit node", stream_id);
                        break;
                    }
                    Some(m) => {
                        debug!(
                            "Unexpected command {} on stream {}, ignoring",
                            m.command, stream_id
                        );
                    }
                    None => {
                        debug!("Circuit reader channel closed for stream {}", stream_id);
                        break;
                    }
                }
            }
        }
    }

    cleanup_stream(&circuit, socks_stream, stream_id).await;
    metrics.push_event(EventKind::StreamEnd {
        circuit_id,
        stream_id,
    });
    info!("Stream {} on circuit {} closed", stream_id, circuit_id);

    Ok(())
}

/// Best-effort cleanup: send END message and unregister stream from circuit.
async fn cleanup_stream(
    circuit: &Arc<Mutex<Circuit>>,
    socks_stream: &mut TcpStream,
    stream_id: common::StreamId,
) {
    {
        let mut c = circuit.lock().await;
        if let Err(e) = c.send_message(stream_id, MessageCommand::End, &[]).await {
            debug!(
                "Failed to send END for stream {} (best-effort): {}",
                stream_id, e
            );
        }
    }

    {
        let mut c = circuit.lock().await;
        c.unregister_stream(stream_id);
    }

    let _ = socks_stream.shutdown().await;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_timeout_is_reasonable() {
        // Ensure the timeout is set to a reasonable value
        assert!(CONNECTED_TIMEOUT.as_secs() >= 10);
        assert!(CONNECTED_TIMEOUT.as_secs() <= 120);
    }

    #[test]
    fn test_socks5_buffer_size() {
        // Buffer should be at least 1KB for reasonable throughput
        assert!(SOCKS5_READ_BUF_SIZE >= 1024);
        // Buffer should not be excessively large
        assert!(SOCKS5_READ_BUF_SIZE <= 65536);
    }
}
