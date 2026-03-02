//! Relay node TUI metrics --- event types and counters
//!
//! Defines relay-specific event kinds and the [`RelayMetrics`] struct
//! that drives the TUI dashboard. Uses the shared [`common::metrics`]
//! infrastructure for the event buffer and formatting.

use common::metrics::{Direction, EventBuffer};
use common::protocol::{CircuitId, MessageCommand, StreamId};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Default capacity for the event ring buffer
const EVENT_BUFFER_CAPACITY: usize = 200;

/// Relay-specific event types for the TUI activity log
pub enum EventKind {
    /// A new TCP connection was accepted from the previous hop
    ConnectionAccepted { peer: String },
    /// A TCP connection was closed
    ConnectionClosed { peer: String },
    /// A CREATE handshake completed (new circuit established)
    CircuitCreated { circuit_id: CircuitId },
    /// An EXTEND was processed (connected to next hop)
    CircuitExtended {
        circuit_id: CircuitId,
        next_hop: String,
    },
    /// A circuit was destroyed
    CircuitDestroyed { circuit_id: CircuitId },
    /// A relay cell was forwarded (entry/middle: peeled one layer and forwarded)
    RelayForward {
        circuit_id: CircuitId,
        command: MessageCommand,
        bytes: usize,
    },
    /// A relay cell was received backward and re-encrypted
    RelayBackward {
        circuit_id: CircuitId,
        command: MessageCommand,
        bytes: usize,
    },
    /// Exit node: a BEGIN opened a stream to a destination
    StreamOpened {
        circuit_id: CircuitId,
        stream_id: StreamId,
        destination: String,
    },
    /// Exit node: a stream was closed
    StreamClosed {
        circuit_id: CircuitId,
        stream_id: StreamId,
    },
    /// Exit node: data relayed between circuit and destination
    StreamData {
        circuit_id: CircuitId,
        stream_id: StreamId,
        bytes: usize,
        direction: Direction,
    },
    /// An error occurred
    Error { message: String },
}

/// Aggregate metrics for the relay node TUI
pub struct RelayMetrics {
    /// Total TCP connections accepted
    pub connections_accepted: AtomicU64,
    /// Total circuits created
    pub circuits_created: AtomicU64,
    /// Total circuits destroyed
    pub circuits_destroyed: AtomicU64,
    /// Total bytes forwarded (forward direction)
    pub bytes_forwarded: AtomicU64,
    /// Total bytes received (backward direction)
    pub bytes_received: AtomicU64,
    /// Total streams opened (exit node only)
    pub streams_opened: AtomicU64,
    /// Structured event buffer for the activity log
    pub events: EventBuffer<EventKind>,
    /// Service start time
    pub start_time: Instant,
}

impl RelayMetrics {
    /// Create a new metrics instance wrapped in Arc
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

    /// Push an event into the ring buffer
    pub fn push_event(&self, kind: EventKind) {
        self.events.push(kind);
    }

    /// Get the current uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Read connections counter
    pub fn get_connections(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
    }

    /// Read circuits created counter
    pub fn get_circuits_created(&self) -> u64 {
        self.circuits_created.load(Ordering::Relaxed)
    }

    /// Read circuits destroyed counter
    pub fn get_circuits_destroyed(&self) -> u64 {
        self.circuits_destroyed.load(Ordering::Relaxed)
    }

    /// Read bytes forwarded counter
    pub fn get_bytes_forwarded(&self) -> u64 {
        self.bytes_forwarded.load(Ordering::Relaxed)
    }

    /// Read bytes received counter
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Read streams opened counter
    pub fn get_streams_opened(&self) -> u64 {
        self.streams_opened.load(Ordering::Relaxed)
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
