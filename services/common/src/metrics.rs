//! Shared TUI metrics infrastructure.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Timestamped event for TUI display, generic over service-specific event kinds.
pub struct TuiEvent<E> {
    pub elapsed: Duration,
    pub kind: E,
}

/// Thread-safe ring buffer for TUI events with a fixed capacity.
pub struct EventBuffer<E> {
    inner: Mutex<EventBufferInner<E>>,
}

struct EventBufferInner<E> {
    events: VecDeque<TuiEvent<E>>,
    capacity: usize,
    start_time: Instant,
}

impl<E> EventBuffer<E> {
    /// Create a new event buffer with the given maximum capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(EventBufferInner {
                events: VecDeque::with_capacity(capacity),
                capacity,
                start_time: Instant::now(),
            }),
        }
    }

    /// Push a new event, dropping the oldest if at capacity.
    pub fn push(&self, kind: E) {
        if let Ok(mut inner) = self.inner.lock() {
            let elapsed = inner.start_time.elapsed();
            if inner.events.len() >= inner.capacity {
                inner.events.pop_front();
            }
            inner.events.push_back(TuiEvent { elapsed, kind });
        }
    }

    /// Snapshot all events via a mapping function (doesn't hold the lock during rendering).
    pub fn snapshot<F, T>(&self, map_fn: F) -> Vec<T>
    where
        F: Fn(&TuiEvent<E>) -> T,
    {
        if let Ok(inner) = self.inner.lock() {
            inner.events.iter().map(&map_fn).collect()
        } else {
            Vec::new()
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.events.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn start_time(&self) -> Instant {
        self.inner
            .lock()
            .map(|inner| inner.start_time)
            .unwrap_or_else(|_| Instant::now())
    }
}

/// Direction of data flow through the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Forward => write!(f, "fwd"),
            Direction::Backward => write!(f, "bwd"),
        }
    }
}

/// Format a byte count into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format a duration into a compact string (e.g. "2m30s").
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Format a duration as a timestamp offset (e.g. "+0:01:23").
pub fn format_timestamp(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("+{h}:{m:02}:{s:02}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(150)), "2m30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h0m");
        assert_eq!(format_duration(Duration::from_secs(4980)), "1h23m");
    }

    #[test]
    fn test_format_timestamp() {
        assert_eq!(format_timestamp(Duration::from_secs(5)), "+0:00:05");
        assert_eq!(format_timestamp(Duration::from_secs(83)), "+0:01:23");
        assert_eq!(format_timestamp(Duration::from_secs(3912)), "+1:05:12");
    }

    #[test]
    fn test_event_buffer_push_and_snapshot() {
        let buffer: EventBuffer<String> = EventBuffer::new(3);
        buffer.push("first".to_string());
        buffer.push("second".to_string());

        let events = buffer.snapshot(|e| e.kind.clone());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "first");
        assert_eq!(events[1], "second");
    }

    #[test]
    fn test_event_buffer_capacity_overflow() {
        let buffer: EventBuffer<u32> = EventBuffer::new(2);
        buffer.push(1);
        buffer.push(2);
        buffer.push(3); // should drop 1

        let events = buffer.snapshot(|e| e.kind);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], 2);
        assert_eq!(events[1], 3);
    }

    #[test]
    fn test_event_buffer_empty() {
        let buffer: EventBuffer<u32> = EventBuffer::new(10);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push(42);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::Forward.to_string(), "fwd");
        assert_eq!(Direction::Backward.to_string(), "bwd");
    }
}
