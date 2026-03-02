//! Discovery service TUI metrics — event types and counters
//!
//! Defines discovery-specific event kinds and the [`DiscoveryMetrics`] struct
//! that drives the TUI dashboard. Uses the shared [`common::metrics`]
//! infrastructure for the event buffer and formatting.

use common::metrics::EventBuffer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Default capacity for the event ring buffer
const EVENT_BUFFER_CAPACITY: usize = 200;

/// Discovery-specific event types for the TUI activity log
pub enum EventKind {
    /// A relay node registered (or re-registered)
    NodeRegistered {
        node_id: String,
        node_type: String,
        address: String,
    },
    /// A relay node was removed
    NodeRemoved { node_id: String },
    /// A relay node sent a heartbeat
    Heartbeat { node_id: String },
    /// A client requested a random 3-hop path
    PathRequested,
    /// Stale nodes were cleaned up
    StaleCleanup { removed: usize },
    /// Stats endpoint was queried
    StatsQueried,
    /// Health/readiness check
    HealthCheck { ready: bool },
    /// An error occurred
    Error { message: String },
}

/// Aggregate metrics for the discovery service TUI
pub struct DiscoveryMetrics {
    /// Total node registrations
    pub registrations: AtomicU64,
    /// Total node removals
    pub removals: AtomicU64,
    /// Total heartbeats received
    pub heartbeats: AtomicU64,
    /// Total path requests
    pub path_requests: AtomicU64,
    /// Total stale nodes cleaned up
    pub stale_cleaned: AtomicU64,
    /// Structured event buffer for the activity log
    pub events: EventBuffer<EventKind>,
    /// Service start time
    pub start_time: Instant,
}

impl DiscoveryMetrics {
    /// Create a new metrics instance wrapped in Arc
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

    /// Push an event into the ring buffer
    pub fn push_event(&self, kind: EventKind) {
        self.events.push(kind);
    }

    /// Get the current uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Read registrations counter
    pub fn get_registrations(&self) -> u64 {
        self.registrations.load(Ordering::Relaxed)
    }

    /// Read removals counter
    pub fn get_removals(&self) -> u64 {
        self.removals.load(Ordering::Relaxed)
    }

    /// Read heartbeats counter
    pub fn get_heartbeats(&self) -> u64 {
        self.heartbeats.load(Ordering::Relaxed)
    }

    /// Read path requests counter
    pub fn get_path_requests(&self) -> u64 {
        self.path_requests.load(Ordering::Relaxed)
    }

    /// Read stale cleaned counter
    pub fn get_stale_cleaned(&self) -> u64 {
        self.stale_cleaned.load(Ordering::Relaxed)
    }
}
