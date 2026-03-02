//! Tor client TUI metrics — event types and counters
//!
//! Defines the client-specific event kinds and metrics struct
//! that drive the TUI dashboard. Uses the shared [`common::metrics`]
//! infrastructure for the event buffer and formatting.

use common::metrics::{Direction, EventBuffer};
use common::{CircuitId, StreamId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Default capacity for the event ring buffer
const EVENT_BUFFER_CAPACITY: usize = 200;

/// A circuit's path info for TUI display
pub struct CircuitInfo {
    /// Circuit ID
    pub circuit_id: CircuitId,
    /// Entry node address
    pub entry_addr: SocketAddr,
    /// Middle node address
    pub middle_addr: SocketAddr,
    /// Exit node address
    pub exit_addr: SocketAddr,
    /// When this circuit was built
    pub created_at: Instant,
}

impl CircuitInfo {
    /// Format the path as a compact string for table display
    pub fn path_display(&self) -> String {
        format!(
            ":{} \u{2192} :{} \u{2192} :{}",
            self.entry_addr.port(),
            self.middle_addr.port(),
            self.exit_addr.port()
        )
    }
}

/// Client-specific event types for the TUI activity log
pub enum EventKind {
    /// A new circuit was built successfully
    CircuitBuilt { circuit_id: CircuitId, path: String },
    /// A failed circuit was replaced with a new one
    CircuitReplaced {
        old_id: CircuitId,
        new_id: CircuitId,
    },
    /// A circuit was closed (entry node disconnected or error)
    CircuitClosed { circuit_id: CircuitId },
    /// A SOCKS5 client connected with a CONNECT request
    Socks5Accept {
        addr: SocketAddr,
        destination: String,
    },
    /// A BEGIN message was sent to open a stream
    StreamBegin {
        circuit_id: CircuitId,
        stream_id: StreamId,
        destination: String,
    },
    /// A CONNECTED response was received from the exit node
    StreamConnected {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    /// Data was relayed (forward or backward)
    StreamData {
        circuit_id: CircuitId,
        stream_id: StreamId,
        bytes: usize,
        direction: Direction,
    },
    /// A stream was closed
    StreamEnd {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    /// An error occurred
    Error { message: String },
}

/// Aggregate metrics for the Tor client TUI
pub struct ClientMetrics {
    /// Total SOCKS5 connections accepted
    pub connections_accepted: AtomicU64,
    /// Total circuits built (including replacements)
    pub circuits_built: AtomicU64,
    /// Total circuits replaced due to failure
    pub circuits_replaced: AtomicU64,
    /// Total bytes sent (forward direction, after onion encryption)
    pub bytes_sent: AtomicU64,
    /// Total bytes received (backward direction, before onion decryption)
    pub bytes_received: AtomicU64,
    /// Structured event buffer for the activity log
    pub events: EventBuffer<EventKind>,
    /// Service start time
    pub start_time: Instant,
}

impl ClientMetrics {
    /// Create a new metrics instance
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

    /// Push an event into the ring buffer
    pub fn push_event(&self, kind: EventKind) {
        self.events.push(kind);
    }

    /// Get the current uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Read a counter value (relaxed ordering — fine for display)
    pub fn get_connections(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
    }

    /// Read a counter value
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Read a counter value
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
