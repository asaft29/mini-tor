//! Relay node TUI dashboard.

use crate::circuit::CircuitRegistry;
use crate::circuit::handler::CircuitState;
use crate::core::metrics::{EventKind, RelayMetrics};
use anyhow::{Context, Result};
use common::NodeType;
use common::metrics::{Direction, format_bytes, format_duration, format_timestamp};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const TICK_RATE: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, PartialEq, Eq)]
enum FilterMode {
    All,
    Circuits,
    Streams,
    Errors,
}

impl std::fmt::Display for FilterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterMode::All => write!(f, "All"),
            FilterMode::Circuits => write!(f, "Circuits"),
            FilterMode::Streams => write!(f, "Streams"),
            FilterMode::Errors => write!(f, "Errors"),
        }
    }
}

struct TuiState {
    paused: bool,
    filter: FilterMode,
}

/// Run the TUI dashboard until the user quits (q / Ctrl+C).
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

    let state = TuiState {
        paused: false,
        filter: FilterMode::All,
    };

    let result = run_event_loop(
        &mut terminal,
        &metrics,
        &circuit_registry,
        node_type,
        &bind_addr,
        state,
    )
    .await;

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    metrics: &Arc<RelayMetrics>,
    circuit_registry: &Arc<Mutex<CircuitRegistry>>,
    node_type: NodeType,
    bind_addr: &str,
    mut state: TuiState,
) -> Result<bool> {
    loop {
        let (circuit_count, circuit_rows) = {
            let reg = circuit_registry.lock().await;
            let count = reg.circuit_count();
            let summaries = reg.circuit_summaries();
            (count, summaries)
        };
        let event_lines = collect_event_lines(metrics, state.filter);

        terminal
            .draw(|frame| {
                render_ui(
                    frame,
                    metrics,
                    &circuit_rows,
                    &event_lines,
                    node_type,
                    bind_addr,
                    circuit_count,
                    &state,
                );
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
                KeyCode::Char('p') | KeyCode::Char('P') => state.paused = !state.paused,
                KeyCode::Char('1') => state.filter = FilterMode::All,
                KeyCode::Char('2') => state.filter = FilterMode::Circuits,
                KeyCode::Char('3') => state.filter = FilterMode::Streams,
                KeyCode::Char('4') => state.filter = FilterMode::Errors,
                _ => {}
            }
        }
    }
}

fn build_header_spans(
    metrics: &RelayMetrics,
    node_type: NodeType,
    bind_addr: &str,
    circuit_count: usize,
) -> Vec<Span<'static>> {
    let uptime = format_duration(metrics.uptime());
    let conns = metrics.get_connections();
    let created = metrics.get_circuits_created();
    let destroyed = metrics.get_circuits_destroyed();
    let fwd = format_bytes(metrics.get_bytes_forwarded());
    let recv = format_bytes(metrics.get_bytes_received());

    let (type_str, type_color) = match node_type {
        NodeType::Entry => ("ENTRY", Color::Green),
        NodeType::Middle => ("MIDDLE", Color::Yellow),
        NodeType::Exit => ("EXIT", Color::Red),
    };

    let mut spans = vec![
        Span::styled(
            format!(" {type_str} "),
            Style::default()
                .fg(Color::Black)
                .bg(type_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {bind_addr} "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" \u{2502} Up {uptime} ")),
        Span::raw(format!("\u{2502} Conns {conns} ")),
        Span::raw(format!(
            "\u{2502} Circuits {circuit_count} active / {created} total / {destroyed} destroyed "
        )),
        Span::raw(format!("\u{2502} \u{2191} {fwd} \u{2193} {recv}")),
    ];

    if node_type == NodeType::Exit {
        let streams = metrics.get_streams_opened();
        spans.push(Span::raw(format!(" \u{2502} Streams {streams}")));
    }

    spans
}

fn collect_event_lines(metrics: &RelayMetrics, filter: FilterMode) -> Vec<Line<'static>> {
    metrics
        .events
        .snapshot(|evt| {
            if matches_event(&evt.kind, filter) {
                let ts = format_timestamp(evt.elapsed);
                Some(format_event(&ts, &evt.kind))
            } else {
                None
            }
        })
        .into_iter()
        .flatten()
        .collect()
}

fn matches_event(kind: &EventKind, filter: FilterMode) -> bool {
    match filter {
        FilterMode::All => true,
        FilterMode::Circuits => matches!(
            kind,
            EventKind::CircuitCreated { .. }
                | EventKind::CircuitExtended { .. }
                | EventKind::CircuitDestroyed { .. }
        ),
        FilterMode::Streams => matches!(
            kind,
            EventKind::StreamOpened { .. }
                | EventKind::StreamClosed { .. }
                | EventKind::StreamData { .. }
        ),
        FilterMode::Errors => matches!(kind, EventKind::Error { .. }),
    }
}

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

#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
fn render_ui(
    frame: &mut Frame,
    metrics: &RelayMetrics,
    circuit_rows: &[(u32, CircuitState)],
    event_lines: &[Line<'_>],
    node_type: NodeType,
    bind_addr: &str,
    circuit_count: usize,
    state: &TuiState,
) {
    let area = frame.area();

    let (type_str, type_color) = match node_type {
        NodeType::Entry => ("Entry", Color::Green),
        NodeType::Middle => ("Middle", Color::Yellow),
        NodeType::Exit => ("Exit", Color::Red),
    };

    let has_circuits = !circuit_rows.is_empty();

    let layout_constraints = if has_circuits {
        vec![
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Percentage(50),
            Constraint::Min(3),
            Constraint::Length(1),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Percentage(60),
            Constraint::Min(3),
            Constraint::Length(1),
        ]
    };

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints(layout_constraints)
        .split(area);

    let title_area = chunks.first().copied().unwrap_or(area);
    let stats_area = chunks.get(1).copied().unwrap_or(area);

    let header_spans = build_header_spans(metrics, node_type, bind_addr, circuit_count);
    let title = Paragraph::new(Line::from(header_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {type_str} Relay ")),
    );
    frame.render_widget(title, title_area);

    let created = metrics.get_circuits_created();
    let destroyed = metrics.get_circuits_destroyed();
    let conns = metrics.get_connections();
    let fwd = format_bytes(metrics.get_bytes_forwarded());
    let recv = format_bytes(metrics.get_bytes_received());
    let uptime = format_duration(metrics.uptime());

    let stats_lines = if node_type == NodeType::Exit {
        let streams = metrics.get_streams_opened();
        vec![
            Line::from(vec![
                Span::styled(" Uptime    ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{uptime:<20}")),
                Span::styled(" Connections ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{conns}")),
            ]),
            Line::from(vec![
                Span::styled(" Created   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{created:<20}")),
                Span::styled(" Streams     ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{streams}")),
            ]),
            Line::from(vec![
                Span::styled(" Destroyed ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{destroyed:<20}")),
                Span::styled(" \u{2191} Forward   ", Style::default().fg(Color::DarkGray)),
                Span::raw(fwd),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled(" Uptime    ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{uptime:<20}")),
                Span::styled(" Connections ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{conns}")),
            ]),
            Line::from(vec![
                Span::styled(" Created   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{created:<20}")),
                Span::styled(" \u{2191} Forward   ", Style::default().fg(Color::DarkGray)),
                Span::raw(fwd),
            ]),
            Line::from(vec![
                Span::styled(" Destroyed ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{destroyed:<20}")),
                Span::styled(" \u{2193} Received  ", Style::default().fg(Color::DarkGray)),
                Span::raw(recv),
            ]),
        ]
    };

    let stats =
        Paragraph::new(stats_lines).block(Block::default().borders(Borders::ALL).title(" Stats "));
    frame.render_widget(stats, stats_area);

    let mut current_chunk = 2;

    if has_circuits {
        let circuit_area = chunks.get(current_chunk).copied().unwrap_or(area);
        current_chunk += 1;

        let table_header = Row::new(vec![
            Cell::from("CID").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("State").style(Style::default().add_modifier(Modifier::BOLD)),
        ]);

        let table_rows: Vec<Row> = circuit_rows
            .iter()
            .map(|(id, st)| {
                let (state_str, state_color) = match st {
                    CircuitState::Initializing => ("Init", Color::Yellow),
                    CircuitState::Active => ("Active", Color::Green),
                    CircuitState::Closing => ("Closing", Color::Magenta),
                    CircuitState::Closed => ("Closed", Color::Red),
                };
                Row::new(vec![
                    Cell::from(format!("{id:05}")),
                    Cell::from(state_str).style(Style::default().fg(state_color)),
                ])
            })
            .collect();

        let circuit_table = Table::new(table_rows, [Constraint::Length(8), Constraint::Length(10)])
            .header(table_header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Circuits ({circuit_count}) ")),
            );
        frame.render_widget(circuit_table, circuit_area);
    }

    let events_area = chunks.get(current_chunk).copied().unwrap_or(area);
    current_chunk += 1;

    let filter_suffix = match state.filter {
        FilterMode::All => String::new(),
        _ => format!("[{}] ", state.filter),
    };
    let pause_suffix = if state.paused { "[PAUSED] " } else { "" };
    let total_events = event_lines.len();

    let visible_height = events_area.height.saturating_sub(2) as usize;
    let skip = total_events.saturating_sub(visible_height);
    let visible_lines: Vec<Line> = event_lines.iter().skip(skip).cloned().collect();

    let events_widget =
        Paragraph::new(visible_lines).block(Block::default().borders(Borders::ALL).title(format!(
            " Activity Log ({total_events}) {pause_suffix}{filter_suffix}"
        )));
    frame.render_widget(events_widget, events_area);

    let help_area = chunks.get(current_chunk).copied().unwrap_or(area);

    let filter_indicator = match state.filter {
        FilterMode::All => "All",
        FilterMode::Circuits => "Circuits",
        FilterMode::Streams => "Streams",
        FilterMode::Errors => "Errors",
    };

    let help = Paragraph::new(Line::from(vec![
        Span::styled(
            " p",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" Pause ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " 1",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" All ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " 2",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" Circuits ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " 3",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" Streams ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " 4",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" Errors ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " q",
            Style::default().add_modifier(Modifier::BOLD).fg(type_color),
        ),
        Span::styled(" Quit ", Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(
            format!("Filter: {filter_indicator}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    frame.render_widget(help, help_area);
}
