//! Discovery service TUI metrics — event types and counters.

use common::metrics::EventBuffer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const EVENT_BUFFER_CAPACITY: usize = 200;

/// Discovery-specific event types for the TUI activity log.
pub enum EventKind {
    NodeRegistered {
        node_id: String,
        node_type: String,
        address: String,
    },
    NodeRemoved {
        node_id: String,
    },
    Heartbeat {
        node_id: String,
    },
    PathRequested,
    StaleCleanup {
        removed: usize,
    },
    StatsQueried,
    HealthCheck {
        ready: bool,
    },
    Error {
        message: String,
    },
}

/// Aggregate metrics for the discovery service TUI.
pub struct DiscoveryMetrics {
    pub registrations: AtomicU64,
    pub removals: AtomicU64,
    pub heartbeats: AtomicU64,
    pub path_requests: AtomicU64,
    pub stale_cleaned: AtomicU64,
    pub events: EventBuffer<EventKind>,
    pub start_time: Instant,
}

impl DiscoveryMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registrations: AtomicU64::new(0),
            removals: AtomicU64::new(0),
            heartbeats: AtomicU64::new(0),
            path_requests: AtomicU64::new(0),
            stale_cleaned: AtomicU64::new(0),
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

    pub fn get_registrations(&self) -> u64 {
        self.registrations.load(Ordering::Relaxed)
    }

    pub fn get_removals(&self) -> u64 {
        self.removals.load(Ordering::Relaxed)
    }

    pub fn get_heartbeats(&self) -> u64 {
        self.heartbeats.load(Ordering::Relaxed)
    }

    pub fn get_path_requests(&self) -> u64 {
        self.path_requests.load(Ordering::Relaxed)
    }

    pub fn get_stale_cleaned(&self) -> u64 {
        self.stale_cleaned.load(Ordering::Relaxed)
    }
}
