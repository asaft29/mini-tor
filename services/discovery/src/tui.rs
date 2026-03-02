//! Discovery service TUI dashboard
//!
//! Renders a live terminal UI showing the registry status, a node table
//! with all registered relay nodes, and a scrollable activity log of
//! API events (registrations, heartbeats, path requests, stale cleanups).

use crate::metrics::{DiscoveryMetrics, EventKind};
use crate::registry::NodeRegistry;
use anyhow::{Context, Result};
use common::metrics::{format_bytes, format_duration, format_timestamp};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use std::io::stdout;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// TUI refresh rate
const TICK_RATE: Duration = Duration::from_millis(200);

/// Run the TUI dashboard until the user quits (q / Ctrl+C)
///
/// Returns `Ok(true)` if the user requested shutdown.
///
/// # Errors
/// Returns an error if terminal setup or rendering fails.
pub async fn run_tui(
    metrics: Arc<DiscoveryMetrics>,
    registry: Arc<RwLock<NodeRegistry>>,
    bind_addr: String,
) -> Result<bool> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_event_loop(&mut terminal, &metrics, &registry, &bind_addr).await;

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

/// Main event loop
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    metrics: &Arc<DiscoveryMetrics>,
    registry: &Arc<RwLock<NodeRegistry>>,
    bind_addr: &str,
) -> Result<bool> {
    loop {
        // Collect data under lock, then release
        let (node_rows, ready, stats) = {
            let reg = registry.read().await;
            let nodes = reg.get_all_nodes();
            let ready = reg.is_ready();
            let stats = reg.get_stats();

            let now = Instant::now();
            let rows: Vec<NodeRow> = nodes
                .iter()
                .map(|n| {
                    // We can't get heartbeat age from NodeDescriptor alone —
                    // but the stats give us aggregate info. For per-node age,
                    // we use registered_at which is approximate here.
                    NodeRow {
                        node_id: truncate_id(&n.node_id, 12),
                        node_type: format!("{}", n.node_type),
                        address: n.address.to_string(),
                        bandwidth: format_bytes(n.bandwidth),
                        _registered: now,
                    }
                })
                .collect();

            (rows, ready, stats)
        };

        let header_text = build_header(metrics, bind_addr, ready, &stats);
        let event_lines = collect_event_lines(metrics);

        terminal
            .draw(|frame| {
                render_ui(frame, &header_text, &node_rows, &event_lines, ready);
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

/// Truncate a node ID for display
fn truncate_id(id: &str, max_len: usize) -> String {
    if id.len() <= max_len {
        id.to_string()
    } else {
        let end = id.get(..max_len).unwrap_or(id);
        format!("{end}..")
    }
}

/// A row in the node table
struct NodeRow {
    node_id: String,
    node_type: String,
    address: String,
    bandwidth: String,
    _registered: Instant,
}

/// Build the header text with global stats
fn build_header(
    metrics: &DiscoveryMetrics,
    bind_addr: &str,
    ready: bool,
    stats: &crate::registry::RegistryStats,
) -> String {
    let uptime = format_duration(metrics.uptime());
    let ready_str = if ready { "YES" } else { "NO" };
    let regs = metrics.get_registrations();
    let hb = metrics.get_heartbeats();
    let paths = metrics.get_path_requests();
    let cleaned = metrics.get_stale_cleaned();

    format!(
        " DISCOVERY  |  {bind_addr}  |  Up: {uptime}  |  Ready: {ready_str}  |  Nodes: {} (E:{} M:{} X:{})  |  Regs: {regs}  HBs: {hb}  Paths: {paths}  Cleaned: {cleaned}",
        stats.total_nodes, stats.entry_count, stats.middle_count, stats.exit_count
    )
}

/// Collect events from the ring buffer as formatted Lines
fn collect_event_lines(metrics: &DiscoveryMetrics) -> Vec<Line<'static>> {
    metrics.events.snapshot(|evt| {
        let ts = format_timestamp(evt.elapsed);
        format_event(&ts, &evt.kind)
    })
}

/// Format a single event into a colored Line for the TUI
fn format_event<'a>(timestamp: &str, kind: &EventKind) -> Line<'a> {
    match kind {
        EventKind::NodeRegistered {
            node_id,
            node_type,
            address,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "+ REGISTER ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{node_type} {node_id} @ {address}")),
        ]),
        EventKind::NodeRemoved { node_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "- REMOVE   ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(node_id.to_string()),
        ]),
        EventKind::Heartbeat { node_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2665} HEARTBEAT ", Style::default().fg(Color::Cyan)),
            Span::raw(node_id.to_string()),
        ]),
        EventKind::PathRequested => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2192} PATH      ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("random 3-hop path requested"),
        ]),
        EventKind::StaleCleanup { removed } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2717} CLEANUP   ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{removed} stale node(s) removed")),
        ]),
        EventKind::StatsQueried => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("\u{2139} STATS     ", Style::default().fg(Color::Blue)),
            Span::raw("stats queried"),
        ]),
        EventKind::HealthCheck { ready } => {
            let status = if *ready { "ready" } else { "NOT ready" };
            Line::from(vec![
                Span::styled(
                    format!(" {timestamp} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled("\u{2139} HEALTH    ", Style::default().fg(Color::Blue)),
                Span::raw(format!("check: {status}")),
            ])
        }
        EventKind::Error { message } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2717} ERROR     ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(message.clone(), Style::default().fg(Color::Red)),
        ]),
    }
}

/// Render the full UI layout
fn render_ui(
    frame: &mut Frame,
    header_text: &str,
    node_rows: &[NodeRow],
    event_lines: &[Line<'_>],
    ready: bool,
) {
    let area = frame.area();

    // 3-panel layout: header, node table (40%), event log (60%)
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // header
            Constraint::Percentage(40), // node table
            Constraint::Percentage(60), // event log
        ])
        .split(area);

    let header_area = chunks.first().copied().unwrap_or(area);
    let table_area = chunks.get(1).copied().unwrap_or(area);
    let events_area = chunks.get(2).copied().unwrap_or(area);

    // Header
    let ready_indicator = if ready { "\u{2713}" } else { "\u{2717}" };
    let header = Paragraph::new(header_text.to_string())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Discovery Dashboard [{ready_indicator}] ")),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(header, header_area);

    // Node table
    let header_row = Row::new(vec![
        Cell::from("ID").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Address").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Bandwidth").style(Style::default().add_modifier(Modifier::BOLD)),
    ]);

    let rows: Vec<Row> = node_rows
        .iter()
        .map(|n| {
            let type_color = match n.node_type.as_str() {
                "Entry" => Color::Green,
                "Middle" => Color::Yellow,
                "Exit" => Color::Red,
                _ => Color::White,
            };
            Row::new(vec![
                Cell::from(n.node_id.clone()),
                Cell::from(n.node_type.clone()).style(Style::default().fg(type_color)),
                Cell::from(n.address.clone()),
                Cell::from(n.bandwidth.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Length(8),
            Constraint::Min(21),
            Constraint::Length(10),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Node Registry ({} nodes) ", node_rows.len())),
    );
    frame.render_widget(table, table_area);

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
