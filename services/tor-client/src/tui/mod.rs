//! Tor client TUI dashboard.

use crate::core::circuit::{CircuitPool, CircuitState};
use crate::core::metrics::{ClientMetrics, EventKind};
use anyhow::{Context, Result};
use common::metrics::{Direction, format_bytes, format_duration, format_timestamp};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const TICK_RATE: Duration = Duration::from_millis(200);

/// Run the TUI dashboard until the user quits (q / Ctrl+C).
pub async fn run_tui(
    metrics: Arc<ClientMetrics>,
    pool: Arc<Mutex<CircuitPool>>,
    socks_addr: String,
) -> Result<bool> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = run_event_loop(&mut terminal, &metrics, &pool, &socks_addr).await;

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    metrics: &Arc<ClientMetrics>,
    pool: &Arc<Mutex<CircuitPool>>,
    socks_addr: &str,
) -> Result<bool> {
    loop {
        let circuit_rows = collect_circuit_rows(pool).await;
        let event_lines = collect_event_lines(metrics);
        let header_text = build_header(metrics, socks_addr, &circuit_rows);

        terminal
            .draw(|frame| {
                render_ui(frame, &header_text, &circuit_rows, &event_lines);
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

struct CircuitRow {
    circuit_id: String,
    state: String,
    state_color: Color,
    streams: String,
    age: String,
    path: String,
}

async fn collect_circuit_rows(pool: &Arc<Mutex<CircuitPool>>) -> Vec<CircuitRow> {
    let pool_guard = pool.lock().await;
    let now = std::time::Instant::now();
    let mut rows = Vec::new();

    for (&circuit_id, circuit_arc) in pool_guard.iter_circuits() {
        let circuit = circuit_arc.lock().await;
        let (state_str, state_color) = match circuit.state {
            CircuitState::Building => ("Building", Color::Yellow),
            CircuitState::Ready => ("Ready", Color::Green),
            CircuitState::Dirty => ("Dirty", Color::LightYellow),
            CircuitState::Closing => ("Closing", Color::Magenta),
            CircuitState::Closed => ("Closed", Color::Red),
        };

        let age_str = pool_guard
            .circuit_age(circuit_id, now)
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_default();

        rows.push(CircuitRow {
            circuit_id: format!("{:05}", circuit_id),
            state: state_str.to_string(),
            state_color,
            streams: circuit.active_stream_count().to_string(),
            age: age_str,
            path: circuit
                .path_display
                .as_deref()
                .unwrap_or("unknown")
                .to_string(),
        });
    }

    rows
}

fn build_header(metrics: &ClientMetrics, socks_addr: &str, circuits: &[CircuitRow]) -> String {
    let uptime = format_duration(metrics.uptime());
    let ready_count = circuits.iter().filter(|c| c.state == "Ready").count();
    let total_count = circuits.len();
    let conns = metrics.get_connections();
    let sent = format_bytes(metrics.get_bytes_sent());
    let recv = format_bytes(metrics.get_bytes_received());

    format!(
        " TOR CLIENT  |  SOCKS5: {socks_addr}  |  Up: {uptime}  |  Pool: {ready_count}/{total_count} ready  |  Conns: {conns}  |  \u{2191} {sent}  |  \u{2193} {recv}"
    )
}

fn collect_event_lines(metrics: &ClientMetrics) -> Vec<Line<'static>> {
    metrics.events.snapshot(|evt| {
        let ts = format_timestamp(evt.elapsed);
        format_event(&ts, &evt.kind)
    })
}

fn format_event<'a>(timestamp: &str, kind: &EventKind) -> Line<'a> {
    match kind {
        EventKind::CircuitBuilt { circuit_id, path } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2699} CIRCUIT  ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("Built cid={circuit_id} [{path}]")),
        ]),
        EventKind::CircuitReplaced { old_id, new_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2699} REPLACE  ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("cid={old_id} \u{2192} cid={new_id}")),
        ]),
        EventKind::CircuitClosed { circuit_id } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2717} CLOSED   ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("cid={circuit_id}")),
        ]),
        EventKind::Socks5Accept { addr, destination } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2190} SOCKS5   ",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{addr} \u{2192} {destination}")),
        ]),
        EventKind::StreamBegin {
            circuit_id,
            stream_id,
            destination,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2192} BEGIN    ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "cid={circuit_id} sid={stream_id} \u{2192} {destination}"
            )),
        ]),
        EventKind::StreamConnected {
            circuit_id,
            stream_id,
        } => Line::from(vec![
            Span::styled(
                format!(" {timestamp} "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "\u{2190} CONNECT  ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
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
        EventKind::StreamEnd {
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

fn render_ui(
    frame: &mut Frame,
    header_text: &str,
    circuit_rows: &[CircuitRow],
    event_lines: &[Line<'_>],
) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

    let header_area = chunks.first().copied().unwrap_or(area);
    let circuit_area = chunks.get(1).copied().unwrap_or(area);
    let events_area = chunks.get(2).copied().unwrap_or(area);

    let header = Paragraph::new(header_text.to_string())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Tor Client Dashboard "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(header, header_area);

    let table_header = Row::new(vec![
        Cell::from("CID").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("State").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Streams").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Age").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Path").style(Style::default().add_modifier(Modifier::BOLD)),
    ]);

    let table_rows: Vec<Row> = circuit_rows
        .iter()
        .map(|cr| {
            Row::new(vec![
                Cell::from(cr.circuit_id.clone()),
                Cell::from(cr.state.clone()).style(Style::default().fg(cr.state_color)),
                Cell::from(cr.streams.clone()),
                Cell::from(cr.age.clone()),
                Cell::from(cr.path.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        table_rows,
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Min(20),
        ],
    )
    .header(table_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Circuit Pool "),
    );
    frame.render_widget(table, circuit_area);

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
