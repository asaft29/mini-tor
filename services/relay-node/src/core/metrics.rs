//! Relay node TUI metrics — event types and counters.

use common::metrics::{Direction, EventBuffer, format_bytes, format_timestamp};
use common::protocol::{CircuitId, MessageCommand, StreamId};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const EVENT_BUFFER_CAPACITY: usize = 200;

/// Relay-specific event types for the TUI activity log.
pub enum EventKind {
    ConnectionAccepted {
        peer: String,
    },
    ConnectionClosed {
        peer: String,
    },
    CircuitCreated {
        circuit_id: CircuitId,
    },
    CircuitExtended {
        circuit_id: CircuitId,
        next_hop: String,
    },
    CircuitDestroyed {
        circuit_id: CircuitId,
    },
    RelayForward {
        circuit_id: CircuitId,
        command: MessageCommand,
        bytes: usize,
    },
    RelayBackward {
        circuit_id: CircuitId,
        command: MessageCommand,
        bytes: usize,
    },
    StreamOpened {
        circuit_id: CircuitId,
        stream_id: StreamId,
        destination: String,
    },
    StreamClosed {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    StreamData {
        circuit_id: CircuitId,
        stream_id: StreamId,
        bytes: usize,
        direction: Direction,
    },
    Error {
        message: String,
    },
}

/// Aggregate metrics for the relay node TUI.
pub struct RelayMetrics {
    pub connections_accepted: AtomicU64,
    pub circuits_created: AtomicU64,
    pub circuits_destroyed: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub bytes_received: AtomicU64,
    pub streams_opened: AtomicU64,
    pub events: EventBuffer<EventKind>,
    pub start_time: Instant,
}

impl RelayMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connections_accepted: AtomicU64::new(0),
            circuits_created: AtomicU64::new(0),
            circuits_destroyed: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            events: EventBuffer::new(EVENT_BUFFER_CAPACITY),
            start_time: Instant::now(),
        })
    }

    pub fn push_event(&self, kind: EventKind) {
        self.events.push(kind);
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    pub fn get_connections(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
    }

    pub fn get_circuits_created(&self) -> u64 {
        self.circuits_created.load(Ordering::Relaxed)
    }

    pub fn get_circuits_destroyed(&self) -> u64 {
        self.circuits_destroyed.load(Ordering::Relaxed)
    }

    pub fn get_bytes_forwarded(&self) -> u64 {
        self.bytes_forwarded.load(Ordering::Relaxed)
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_streams_opened(&self) -> u64 {
        self.streams_opened.load(Ordering::Relaxed)
    }

    /// Format recent events for the heartbeat payload.
    pub fn event_snapshot(&self) -> Vec<String> {
        self.events
            .snapshot(|e| {
                let ts = format_timestamp(e.elapsed);
                format!("[{ts}] {}", format_event_string(&e.kind))
            })
            .into_iter()
            .rev()
            .take(20)
            .collect()
    }
}

/// Plain-text relay event formatter for heartbeat / web UI display.
/// Matches the TUI event format: `[timestamp] ICON LABEL    detail`
pub fn format_event_string(kind: &EventKind) -> String {
    match kind {
        EventKind::ConnectionAccepted { peer } => {
            format!("\u{2190} ACCEPT    from {peer}")
        }
        EventKind::ConnectionClosed { peer } => {
            format!("\u{2014} CLOSED    conn from {peer}")
        }
        EventKind::CircuitCreated { circuit_id } => {
            format!("\u{2699} CREATE    cid={circuit_id}")
        }
        EventKind::CircuitExtended {
            circuit_id,
            next_hop,
        } => {
            format!("\u{2192} EXTEND    cid={circuit_id} \u{2192} {next_hop}")
        }
        EventKind::CircuitDestroyed { circuit_id } => {
            format!("\u{2717} DESTROY   cid={circuit_id}")
        }
        EventKind::RelayForward {
            circuit_id,
            command,
            bytes,
        } => {
            format!(
                "\u{2192} RELAY\u{2192}   cid={circuit_id} {command} [{}]",
                format_bytes(*bytes as u64)
            )
        }
        EventKind::RelayBackward {
            circuit_id,
            command,
            bytes,
        } => {
            format!(
                "\u{2190} RELAY\u{2190}   cid={circuit_id} {command} [{}]",
                format_bytes(*bytes as u64)
            )
        }
        EventKind::StreamOpened {
            circuit_id,
            stream_id,
            destination,
        } => {
            format!("\u{2192} STREAM    cid={circuit_id} sid={stream_id} \u{2192} {destination}")
        }
        EventKind::StreamClosed {
            circuit_id,
            stream_id,
        } => {
            format!("\u{2014} END       cid={circuit_id} sid={stream_id}")
        }
        EventKind::StreamData {
            circuit_id,
            stream_id,
            bytes,
            direction: _,
        } => {
            let b = format_bytes(*bytes as u64);
            format!("\u{2194} DATA      cid={circuit_id} sid={stream_id} [{b}]")
        }
        EventKind::Error { message } => {
            format!("\u{2717} ERROR     {message}")
        }
    }
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            circuits_created: AtomicU64::new(0),
            circuits_destroyed: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            events: EventBuffer::new(EVENT_BUFFER_CAPACITY),
            start_time: Instant::now(),
        }
    }
}
