//! Relay node TUI dashboard
//!
//! Renders a live terminal UI showing the relay node type, connection stats,
//! circuit table, byte counters, and a scrollable activity log of protocol-level
//! events flowing through the relay (CREATE/EXTEND, relay cells, stream ops).

use crate::circuit::CircuitRegistry;
use crate::metrics::{EventKind, RelayMetrics};
use anyhow::{Context, Result};
use common::NodeType;
use common::metrics::{Direction, format_bytes, format_duration, format_timestamp};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// TUI refresh rate
const TICK_RATE: Duration = Duration::from_millis(200);

/// Run the TUI dashboard until the user quits (q / Ctrl+C)
///
/// Returns `Ok(true)` if the user requested shutdown.
///
/// # Errors
/// Returns an error if terminal setup or rendering fails
pub async fn run_tui(
    metrics: Arc<RelayMetrics>,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    node_type: NodeType,
    bind_addr: String,
) -> Result<bool> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_event_loop(
        &mut terminal,
        &metrics,
        &circuit_registry,
        node_type,
        &bind_addr,
    )
    .await;

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

/// Main event loop
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    metrics: &Arc<RelayMetrics>,
    circuit_registry: &Arc<Mutex<CircuitRegistry>>,
    node_type: NodeType,
    bind_addr: &str,
) -> Result<bool> {
    loop {
        let circuit_count = {
            let reg = circuit_registry.lock().await;
            reg.circuit_count()
        };
        let event_lines = collect_event_lines(metrics);
        let header_text = build_header(metrics, node_type, bind_addr, circuit_count);

        terminal
            .draw(|frame| {
                render_ui(frame, &header_text, &event_lines, node_type);
            })
            .context("Failed to draw frame")?;

        if event::poll(TICK_RATE).context("Failed to poll events")?
            && let Event::Key(key) = event::read().context("Failed to read event")?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(true),
                KeyCode::Char('c')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    return Ok(true);
                }
                _ => {}
            }
        }
    }
}

/// Build the header text with global stats
fn build_header(
    metrics: &RelayMetrics,
    node_type: NodeType,
    bind_addr: &str,
    circuit_count: usize,
) -> String {
    let uptime = format_duration(metrics.uptime());
    let conns = metrics.get_connections();
    let created = metrics.get_circuits_created();
    let destroyed = metrics.get_circuits_destroyed();
    let fwd = format_bytes(metrics.get_bytes_forwarded());
    let recv = format_bytes(metrics.get_bytes_received());

    let type_str = match node_type {
        NodeType::Entry => "ENTRY",
        NodeType::Middle => "MIDDLE",
        NodeType::Exit => "EXIT",
    };

    let mut header = format!(
        " RELAY [{type_str}]  |  {bind_addr}  |  Up: {uptime}  |  Conns: {conns}  |  Circuits: {circuit_count} active / {created} total / {destroyed} destroyed  |  \u{2191} {fwd}  \u{2193} {recv}"
    );

    if node_type == NodeType::Exit {
        let streams = metrics.get_streams_opened();
        header.push_str(&format!("  |  Streams: {streams}"));
    }

    header
}

/// Collect events from the ring buffer as formatted Lines
fn collect_event_lines(metrics: &RelayMetrics) -> Vec<Line<'static>> {
    metrics.events.snapshot(|evt| {
        let ts = format_timestamp(evt.elapsed);
        format_event(&ts, &evt.kind)
    })
}

/// Format a single event into a colored Line for the TUI
fn format_event<'a>(timestamp: &str, kind: &EventKind) -> Line<'a> {
    match kind {
        EventKind::ConnectionAccepted { peer } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2190} ACCEPT   ",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("from {peer}")),
        ]),
        EventKind::ConnectionClosed { peer } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2014} CLOSED   ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("conn from {peer}")),
        ]),
        EventKind::CircuitCreated { circuit_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2699} CREATE   ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("cid={circuit_id} handshake complete")),
        ]),
        EventKind::CircuitExtended {
            circuit_id,
            next_hop,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2192} EXTEND   ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("cid={circuit_id} \u{2192} {next_hop}")),
        ]),
        EventKind::CircuitDestroyed { circuit_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2717} DESTROY  ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("cid={circuit_id}")),
        ]),
        EventKind::RelayForward {
            circuit_id,
            command,
            bytes,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2192} RELAY\u{2192}  ",
                Style::default().fg(Color::White),
            ),
            Span::raw(format!(
                "cid={circuit_id} {command} [{}]",
                format_bytes(*bytes as u64)
            )),
        ]),
        EventKind::RelayBackward {
            circuit_id,
            command,
            bytes,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2190} RELAY\u{2190}  ", Style::default().fg(Color::Gray)),
            Span::raw(format!(
                "cid={circuit_id} {command} [{}]",
                format_bytes(*bytes as u64)
            )),
        ]),
        EventKind::StreamOpened {
            circuit_id,
            stream_id,
            destination,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2192} STREAM   ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "cid={circuit_id} sid={stream_id} \u{2192} {destination}"
            )),
        ]),
        EventKind::StreamClosed {
            circuit_id,
            stream_id,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2014} END      ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("cid={circuit_id} sid={stream_id}")),
        ]),
        EventKind::StreamData {
            circuit_id,
            stream_id,
            bytes,
            direction,
        } => {
            let (arrow, label, color) = match direction {
                Direction::Forward => ("\u{2192}", "DATA\u{2192}   ", Color::White),
                Direction::Backward => ("\u{2190}", "DATA\u{2190}   ", Color::Gray),
            };
            Line::from(vec![
                Span::styled(
                    format!(" {timestamp} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{arrow} {label}"), Style::default().fg(color)),
                Span::raw(format!(
                    "cid={circuit_id} sid={stream_id} [{} {}]",
                    format_bytes(*bytes as u64),
                    direction
                )),
            ])
        }
        EventKind::Error { message } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2717} ERROR    ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(message.clone(), Style::default().fg(Color::Red)),
        ]),
    }
}

/// Render the full UI layout
fn render_ui(frame: &mut Frame, header_text: &str, event_lines: &[Line<'_>], node_type: NodeType) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    let header_area = chunks.first().copied().unwrap_or(area);
    let events_area = chunks.get(1).copied().unwrap_or(area);

    // Header
    let type_str = match node_type {
        NodeType::Entry => "Entry",
        NodeType::Middle => "Middle",
        NodeType::Exit => "Exit",
    };
    let header = Paragraph::new(header_text.to_string())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {type_str} Relay Dashboard ")),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(header, header_area);

    // Event log (auto-scroll to bottom)
    let visible_height = events_area.height.saturating_sub(2) as usize;
    let total_events = event_lines.len();
    let skip = total_events.saturating_sub(visible_height);

    let visible_lines: Vec<Line> = event_lines.iter().skip(skip).cloned().collect();

    let events_widget = Paragraph::new(visible_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Activity Log ({total_events} events) ")),
    );
    frame.render_widget(events_widget, events_area);
}
