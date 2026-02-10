use crate::circuit::Circuit;
use anyhow::{Context, Result};
use common::MessageCommand;
use simple_socks5::conn::reply::Rep;
use simple_socks5::parse::AddrPort;
use simple_socks5::{ATYP, Socks5};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// Buffer size for reading data from the SOCKS5 client
const SOCKS5_READ_BUF_SIZE: usize = 4096;

/// Handle a single SOCKS5 stream over an onion circuit
///
/// Bridges a SOCKS5 client connection to a destination through the onion circuit:
/// 1. Allocates a stream ID and registers a backward channel with the circuit
/// 2. Sends a BEGIN message (onion-encrypted) to open the stream on the exit node
/// 3. Waits for a CONNECTED response from the exit node
/// 4. Sends a SOCKS5 success reply to the client
/// 5. Relays data bidirectionally (SOCKS5 client <-> circuit) until the stream closes
/// 6. Cleans up by sending END and unregistering the stream
///
/// # Errors
/// Returns an error if stream setup or data relay fails
pub async fn handle_stream(
    circuit: Arc<Mutex<Circuit>>,
    socks_stream: &mut TcpStream,
    destination: String,
) -> Result<()> {
    // 1. Allocate stream ID and register backward channel
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

    // 2. Send BEGIN message with destination (null-terminated)
    let begin_payload = format!("{destination}\0").into_bytes();
    {
        let c = circuit.lock().await;
        c.send_message(stream_id, MessageCommand::Begin, &begin_payload)
            .await
            .context("Failed to send BEGIN message")?;
    }
    debug!("Sent BEGIN for stream {} to {}", stream_id, destination);

    // 3. Wait for CONNECTED response from exit node
    let connected_msg = match rx.recv().await {
        Some(msg) => msg,
        None => {
            // Channel closed before we got a response -- circuit died
            cleanup_stream(&circuit, socks_stream, stream_id).await;
            return Err(anyhow::anyhow!(
                "Circuit closed before CONNECTED received for stream {}",
                stream_id
            ));
        }
    };

    if connected_msg.command != MessageCommand::Connected {
        // Unexpected response -- send SOCKS5 failure and clean up
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

    // 4. Send SOCKS5 success reply to client
    Socks5::send_conn_reply(
        socks_stream,
        Rep::Succeeded,
        ATYP::V4,
        AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
    )
    .await
    .context("Failed to send SOCKS5 success reply")?;

    // 5. Bidirectional relay: SOCKS5 client <-> onion circuit
    let mut buf = [0u8; SOCKS5_READ_BUF_SIZE];

    loop {
        tokio::select! {
            // Forward direction: SOCKS5 client -> circuit -> exit -> destination
            result = socks_stream.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        // SOCKS5 client closed the connection
                        debug!("SOCKS5 client closed stream {}", stream_id);
                        break;
                    }
                    Ok(n) => {
                        let data = buf.get(..n)
                            .ok_or_else(|| anyhow::anyhow!("Buffer read out of range"))?;
                        let c = circuit.lock().await;
                        if let Err(e) = c.send_message(stream_id, MessageCommand::Data, data).await {
                            error!("Failed to send DATA on stream {}: {}", stream_id, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Error reading from SOCKS5 client on stream {}: {}", stream_id, e);
                        break;
                    }
                }
            }

            // Backward direction: destination -> exit -> circuit -> SOCKS5 client
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
                        // Channel closed -- circuit reader terminated
                        debug!("Circuit reader channel closed for stream {}", stream_id);
                        break;
                    }
                }
            }
        }
    }

    // 6. Cleanup: send END and unregister stream
    cleanup_stream(&circuit, socks_stream, stream_id).await;
    info!("Stream {} on circuit {} closed", stream_id, circuit_id);

    Ok(())
}

/// Best-effort cleanup: send END message and unregister stream from circuit
async fn cleanup_stream(
    circuit: &Arc<Mutex<Circuit>>,
    socks_stream: &mut TcpStream,
    stream_id: common::StreamId,
) {
    // Best-effort send END
    {
        let c = circuit.lock().await;
        if let Err(e) = c.send_message(stream_id, MessageCommand::End, &[]).await {
            debug!(
                "Failed to send END for stream {} (best-effort): {}",
                stream_id, e
            );
        }
    }

    // Unregister stream
    {
        let mut c = circuit.lock().await;
        c.unregister_stream(stream_id);
    }

    // Shut down the SOCKS5 side
    let _ = socks_stream.shutdown().await;
}
