use anyhow::{Context, Result};
use common::NodeType;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};
use std::io::stdout;
use std::time::Duration;

use crate::core::config::RelayConfig;

const NODE_TYPES: [NodeType; 3] = [NodeType::Entry, NodeType::Middle, NodeType::Exit];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    NodeType,
    Port,
    Host,
    DirectoryUrl,
    Bandwidth,
    Heartbeat,
    ExitAllowAll,
    OperatorId,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::NodeType => "Node Type",
            Field::Port => "Port",
            Field::Host => "Host",
            Field::DirectoryUrl => "Directory URL",
            Field::Bandwidth => "Bandwidth",
            Field::Heartbeat => "Heartbeat (s)",
            Field::ExitAllowAll => "Exit Allow All",
            Field::OperatorId => "Operator ID",
        }
    }

    fn is_text(self) -> bool {
        !matches!(self, Field::NodeType | Field::ExitAllowAll)
    }
}

struct WizardState {
    focused: usize,
    node_type_idx: usize,
    port: String,
    host: String,
    directory_url: String,
    bandwidth: String,
    heartbeat: String,
    exit_allow_all: bool,
    operator_id: String,
    error: Option<String>,
}

impl WizardState {
    fn new(defaults: &RelayConfig) -> Self {
        let node_type_idx = defaults.node_type.map_or(0, |nt| match nt {
            NodeType::Entry => 0,
            NodeType::Middle => 1,
            NodeType::Exit => 2,
        });
        let exit_allow_all = defaults.node_type == Some(NodeType::Exit) && defaults.exit_allow_all;

        Self {
            focused: 0,
            node_type_idx,
            port: defaults.port.to_string(),
            host: defaults.host.clone(),
            directory_url: defaults.directory_url.clone(),
            bandwidth: defaults.bandwidth.to_string(),
            heartbeat: defaults.heartbeat_interval.to_string(),
            exit_allow_all,
            operator_id: defaults.operator_id.clone().unwrap_or_default(),
            error: None,
        }
    }

    fn active_fields(&self) -> Vec<Field> {
        let mut fields = vec![
            Field::NodeType,
            Field::Port,
            Field::Host,
            Field::DirectoryUrl,
            Field::Bandwidth,
            Field::Heartbeat,
            Field::OperatorId,
        ];
        if self.node_type_idx == 2 {
            fields.insert(6, Field::ExitAllowAll);
        }
        fields
    }

    fn current(&self) -> Option<Field> {
        self.active_fields().get(self.focused).copied()
    }

    fn up(&mut self) {
        if self.focused > 0 {
            self.focused -= 1;
        }
    }

    fn down(&mut self) {
        let max = self.active_fields().len().saturating_sub(1);
        if self.focused < max {
            self.focused += 1;
        }
    }

    fn left(&mut self) {
        match self.current() {
            Some(Field::NodeType) => {
                if self.node_type_idx > 0 {
                    self.node_type_idx -= 1;
                }
            }
            Some(Field::ExitAllowAll) => {
                self.exit_allow_all = false;
            }
            _ => {}
        }
    }

    fn right(&mut self) {
        match self.current() {
            Some(Field::NodeType) => {
                if self.node_type_idx < NODE_TYPES.len() - 1 {
                    self.node_type_idx += 1;
                }
            }
            Some(Field::ExitAllowAll) => {
                self.exit_allow_all = true;
            }
            _ => {}
        }
    }

    fn push_char(&mut self, c: char) {
        if let Some(field) = self.current()
            && field.is_text()
        {
            match field {
                Field::Port => self.port.push(c),
                Field::Host => self.host.push(c),
                Field::DirectoryUrl => self.directory_url.push(c),
                Field::Bandwidth => self.bandwidth.push(c),
                Field::Heartbeat => self.heartbeat.push(c),
                Field::OperatorId => self.operator_id.push(c),
                _ => {}
            }
            self.error = None;
        }
    }

    fn pop_char(&mut self) {
        if let Some(field) = self.current()
            && field.is_text()
        {
            match field {
                Field::Port => {
                    self.port.pop();
                }
                Field::Host => {
                    self.host.pop();
                }
                Field::DirectoryUrl => {
                    self.directory_url.pop();
                }
                Field::Bandwidth => {
                    self.bandwidth.pop();
                }
                Field::Heartbeat => {
                    self.heartbeat.pop();
                }
                Field::OperatorId => {
                    self.operator_id.pop();
                }
                _ => {}
            }
            self.error = None;
        }
    }

    fn validate(&mut self) -> Option<RelayConfig> {
        let node_type = NODE_TYPES.get(self.node_type_idx).copied();

        if node_type.is_none() {
            self.error = Some("Node type is required".to_string());
            return None;
        }
        let node_type = node_type.ok_or("invalid node type").ok()?;

        let port: u16 = match self.port.parse() {
            Ok(p) if p >= 1 => p,
            _ => {
                self.error = Some("Port must be 1\u{2013}65535".to_string());
                return None;
            }
        };

        if self.host.parse::<std::net::IpAddr>().is_err() {
            self.error = Some("Host must be a valid IP address".to_string());
            return None;
        }

        if !self.directory_url.starts_with("http://") && !self.directory_url.starts_with("https://")
        {
            self.error = Some("Directory URL must start with http:// or https://".to_string());
            return None;
        }

        let bandwidth: u64 = match self.bandwidth.parse() {
            Ok(b) if b > 0 => b,
            _ => {
                self.error = Some("Bandwidth must be > 0".to_string());
                return None;
            }
        };

        let heartbeat_interval: u64 = match self.heartbeat.parse() {
            Ok(h) if h > 0 => h,
            _ => {
                self.error = Some("Heartbeat must be > 0".to_string());
                return None;
            }
        };

        self.error = None;
        Some(RelayConfig {
            node_type: Some(node_type),
            port,
            host: self.host.clone(),
            directory_url: self.directory_url.clone(),
            bandwidth,
            heartbeat_interval,
            exit_allow_all: self.exit_allow_all,
            tui: true,
            bind_host: "0.0.0.0".to_string(),
            operator_id: if self.operator_id.is_empty() {
                None
            } else {
                Some(self.operator_id.clone())
            },
        })
    }
}

pub fn run_wizard(defaults: &RelayConfig) -> Result<RelayConfig> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let result = wizard_loop(&mut terminal, defaults);

    disable_raw_mode().ok();
    stdout().execute(LeaveAlternateScreen).ok();

    result
}

fn wizard_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    defaults: &RelayConfig,
) -> Result<RelayConfig> {
    let mut state = WizardState::new(defaults);

    loop {
        terminal
            .draw(|frame| render(frame, &state))
            .context("Failed to draw frame")?;

        if !event::poll(Duration::from_millis(50)).context("Failed to poll events")? {
            continue;
        }

        let Event::Key(key) = event::read().context("Failed to read event")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Esc => std::process::exit(0),
            KeyCode::Up | KeyCode::BackTab => state.up(),
            KeyCode::Down | KeyCode::Tab => state.down(),
            KeyCode::Left => state.left(),
            KeyCode::Right => state.right(),
            KeyCode::Backspace => state.pop_char(),
            KeyCode::Enter => {
                if let Some(config) = state.validate() {
                    return Ok(config);
                }
            }
            KeyCode::Char(c) => {
                if state.current().is_some_and(|f| f.is_text()) {
                    state.push_char(c);
                }
            }
            _ => {}
        }
    }
}

fn render(frame: &mut Frame, state: &WizardState) {
    let area = frame.area();

    let fields = state.active_fields();
    let field_count = fields.len();

    let vertical = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(field_count as u16 + 2),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    let title_area = vertical.first().copied().unwrap_or(area);
    let fields_area = vertical.get(1).copied().unwrap_or(area);
    let status_area = vertical.get(2).copied().unwrap_or(area);
    let help_area = vertical.get(3).copied().unwrap_or(area);

    let title = Paragraph::new(" Relay Node Setup \u{2014} Configure, then press Enter to launch")
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, title_area);

    let rows: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let is_focused = i == state.focused;
            let prefix = if is_focused { "\u{25b6} " } else { "  " };
            let label_style = if is_focused {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            match field {
                Field::NodeType => {
                    let values: Vec<&str> = NODE_TYPES
                        .iter()
                        .map(|nt| match nt {
                            NodeType::Entry => "Entry",
                            NodeType::Middle => "Middle",
                            NodeType::Exit => "Exit",
                        })
                        .collect();
                    let current = values.get(state.node_type_idx).copied().unwrap_or("Entry");
                    let value = format!("\u{25c4}  {}  \u{25ba}", current);
                    let value_style = if is_focused {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(prefix.to_string(), label_style),
                        Span::styled(format!("{:<16}", field.label()), label_style),
                        Span::styled(value, value_style),
                    ])
                }
                Field::ExitAllowAll => {
                    let value = if state.exit_allow_all {
                        "\u{25c4}  Yes  \u{25ba}"
                    } else {
                        "\u{25c4}  No  \u{25ba}"
                    };
                    let value_style = if is_focused {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(prefix.to_string(), label_style),
                        Span::styled(format!("{:<16}", field.label()), label_style),
                        Span::styled(value.to_string(), value_style),
                    ])
                }
                _ => {
                    let text = match field {
                        Field::Port => state.port.as_str(),
                        Field::Host => state.host.as_str(),
                        Field::DirectoryUrl => state.directory_url.as_str(),
                        Field::Bandwidth => state.bandwidth.as_str(),
                        Field::Heartbeat => state.heartbeat.as_str(),
                        Field::OperatorId => state.operator_id.as_str(),
                        _ => "",
                    };
                    let cursor = if is_focused { "\u{2588}" } else { "" };
                    let value_style = if is_focused {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(prefix.to_string(), label_style),
                        Span::styled(format!("{:<16}", field.label()), label_style),
                        Span::styled(text.to_string(), value_style),
                        Span::styled(cursor.to_string(), Style::default().fg(Color::Yellow)),
                    ])
                }
            }
        })
        .collect();

    let fields_widget = Paragraph::new(rows).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Configuration "),
    );
    frame.render_widget(fields_widget, fields_area);

    let status_text = match &state.error {
        Some(err) => {
            let msg: String = err.clone();
            Line::from(vec![
                Span::styled(
                    "\u{2717} ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(msg, Style::default().fg(Color::Red)),
            ])
        }
        None => Line::from(vec![
            Span::styled(
                "\u{2713} ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Ready", Style::default().fg(Color::Green)),
        ]),
    };

    let status = Paragraph::new(status_text).block(Block::default().borders(Borders::ALL));
    frame.render_widget(status, status_area);

    let help = Paragraph::new("\u{2191}\u{2193}/Tab move   \u{25c4}\u{25ba} cycle   Type edit   Backspace   Enter launch   Esc quit")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, help_area);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_default_config() -> RelayConfig {
        RelayConfig {
            node_type: None,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
            tui: true,
            bind_host: "0.0.0.0".to_string(),
            operator_id: None,
        }
    }

    #[test]
    fn test_validate_valid_entry_config() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.node_type_idx = 0;
        let config = state.validate().unwrap();
        assert_eq!(config.node_type, Some(NodeType::Entry));
        assert_eq!(config.port, 9001);
        assert!(config.tui);
    }

    #[test]
    fn test_validate_valid_exit_config() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.node_type_idx = 2;
        state.exit_allow_all = true;
        let config = state.validate().unwrap();
        assert_eq!(config.node_type, Some(NodeType::Exit));
        assert!(config.exit_allow_all);
    }

    #[test]
    fn test_validate_invalid_port() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.port = "0".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_empty_port() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.port = String::new();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_invalid_host() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.host = "not-an-ip".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_invalid_directory_url() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.directory_url = "ftp://bad".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_zero_bandwidth() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.bandwidth = "0".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_zero_heartbeat() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.heartbeat = "0".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_empty_operator_id_becomes_none() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.operator_id = String::new();
        let config = state.validate().unwrap();
        assert!(config.operator_id.is_none());
    }

    #[test]
    fn test_validate_operator_id_set() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.operator_id = "alice".to_string();
        let config = state.validate().unwrap();
        assert_eq!(config.operator_id, Some("alice".to_string()));
    }

    #[test]
    fn test_active_fields_include_exit_allow_all_only_for_exit() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.node_type_idx = 0;
        assert!(!state.active_fields().contains(&Field::ExitAllowAll));
        state.node_type_idx = 2;
        assert!(state.active_fields().contains(&Field::ExitAllowAll));
    }

    #[test]
    fn test_navigation_up_down() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        assert_eq!(state.focused, 0);
        state.down();
        assert_eq!(state.focused, 1);
        state.up();
        assert_eq!(state.focused, 0);
    }

    #[test]
    fn test_selector_left_right_node_type() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.focused = 0;
        assert_eq!(state.node_type_idx, 0);
        state.right();
        assert_eq!(state.node_type_idx, 1);
        state.left();
        assert_eq!(state.node_type_idx, 0);
    }
}
