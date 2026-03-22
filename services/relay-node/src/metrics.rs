//! Relay node TUI metrics — event types and counters.

use common::metrics::{Direction, EventBuffer};
use common::protocol::{CircuitId, MessageCommand, StreamId};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const EVENT_BUFFER_CAPACITY: usize = 200;

/// Relay-specific event types for the TUI activity log.
pub enum EventKind {
    ConnectionAccepted { peer: String },
    ConnectionClosed { peer: String },
    CircuitCreated { circuit_id: CircuitId },
    CircuitExtended {
        circuit_id: CircuitId,
        next_hop: String,
    },
    CircuitDestroyed { circuit_id: CircuitId },
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
    Error { message: String },
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
