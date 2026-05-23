//! Tor client TUI metrics — event types and counters.

use common::metrics::{Direction, EventBuffer};
use common::{CircuitId, StreamId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const EVENT_BUFFER_CAPACITY: usize = 200;

/// A circuit's path info for TUI display.
pub struct CircuitInfo {
    pub circuit_id: CircuitId,
    pub entry_addr: SocketAddr,
    pub middle_addr: SocketAddr,
    pub exit_addr: SocketAddr,
    pub created_at: Instant,
}

impl CircuitInfo {
    pub fn path_display(&self) -> String {
        format!(
            ":{} \u{2192} :{} \u{2192} :{}",
            self.entry_addr.port(),
            self.middle_addr.port(),
            self.exit_addr.port()
        )
    }
}

/// Client-specific event types for the TUI activity log.
pub enum EventKind {
    CircuitBuilt {
        circuit_id: CircuitId,
        path: String,
    },
    CircuitReplaced {
        old_id: CircuitId,
        new_id: CircuitId,
    },
    CircuitClosed {
        circuit_id: CircuitId,
    },
    Socks5Accept {
        addr: SocketAddr,
        destination: String,
    },
    StreamBegin {
        circuit_id: CircuitId,
        stream_id: StreamId,
        destination: String,
    },
    StreamConnected {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    StreamData {
        circuit_id: CircuitId,
        stream_id: StreamId,
        bytes: usize,
        direction: Direction,
    },
    StreamEnd {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    Error {
        message: String,
    },
}

/// Aggregate metrics for the Tor client TUI.
pub struct ClientMetrics {
    pub connections_accepted: AtomicU64,
    pub circuits_built: AtomicU64,
    pub circuits_replaced: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub events: EventBuffer<EventKind>,
    pub start_time: Instant,
}

impl ClientMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connections_accepted: AtomicU64::new(0),
            circuits_built: AtomicU64::new(0),
            circuits_replaced: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
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

    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

impl Default for ClientMetrics {
    fn default() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            circuits_built: AtomicU64::new(0),
            circuits_replaced: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            events: EventBuffer::new(EVENT_BUFFER_CAPACITY),
            start_time: Instant::now(),
        }
    }
}
