use anyhow::{Context, Result};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};
use std::io::stdout;
use std::time::Duration;

use crate::core::config::TorClientConfig;

const MAX_HOPS: usize = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    SocksAddr,
    DirectoryUrl,
    PoolSize,
    Hops,
    MaxRebuildAttempts,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::SocksAddr => "SOCKS Address",
            Field::DirectoryUrl => "Directory URL",
            Field::PoolSize => "Pool Size",
            Field::Hops => "Hops",
            Field::MaxRebuildAttempts => "Max Rebuild",
        }
    }
}

const FIELDS: [Field; 5] = [
    Field::SocksAddr,
    Field::DirectoryUrl,
    Field::PoolSize,
    Field::Hops,
    Field::MaxRebuildAttempts,
];

struct WizardState {
    focused: usize,
    socks_addr: String,
    directory_url: String,
    pool_size: String,
    hops: String,
    max_rebuild_attempts: String,
    error: Option<String>,
}

impl WizardState {
    fn new(defaults: &TorClientConfig) -> Self {
        Self {
            focused: 0,
            socks_addr: defaults.socks_addr.clone(),
            directory_url: defaults.directory_url.clone(),
            pool_size: defaults.pool_size.to_string(),
            hops: defaults.hops.to_string(),
            max_rebuild_attempts: defaults.max_rebuild_attempts.to_string(),
            error: None,
        }
    }

    fn current(&self) -> Option<Field> {
        FIELDS.get(self.focused).copied()
    }

    fn up(&mut self) {
        if self.focused > 0 {
            self.focused -= 1;
        }
    }

    fn down(&mut self) {
        if self.focused < FIELDS.len() - 1 {
            self.focused += 1;
        }
    }

    fn push_char(&mut self, c: char) {
        if let Some(field) = self.current() {
            match field {
                Field::SocksAddr => self.socks_addr.push(c),
                Field::DirectoryUrl => self.directory_url.push(c),
                Field::PoolSize => self.pool_size.push(c),
                Field::Hops => self.hops.push(c),
                Field::MaxRebuildAttempts => self.max_rebuild_attempts.push(c),
            }
            self.error = None;
        }
    }

    fn pop_char(&mut self) {
        if let Some(field) = self.current() {
            match field {
                Field::SocksAddr => {
                    self.socks_addr.pop();
                }
                Field::DirectoryUrl => {
                    self.directory_url.pop();
                }
                Field::PoolSize => {
                    self.pool_size.pop();
                }
                Field::Hops => {
                    self.hops.pop();
                }
                Field::MaxRebuildAttempts => {
                    self.max_rebuild_attempts.pop();
                }
            }
            self.error = None;
        }
    }

    fn validate(&mut self) -> Option<TorClientConfig> {
        if self.socks_addr.parse::<std::net::SocketAddr>().is_err() {
            self.error =
                Some("SOCKS address must be a valid host:port (e.g. 127.0.0.1:1080)".to_string());
            return None;
        }

        if !self.directory_url.starts_with("http://") && !self.directory_url.starts_with("https://")
        {
            self.error = Some("Directory URL must start with http:// or https://".to_string());
            return None;
        }

        let pool_size: usize = match self.pool_size.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                self.error = Some("Pool size must be > 0".to_string());
                return None;
            }
        };

        let hops: usize = match self.hops.parse() {
            Ok(h) if (3..=MAX_HOPS).contains(&h) => h,
            Ok(h) if h < 3 => {
                self.error = Some(format!("Hops must be >= 3, got {h}"));
                return None;
            }
            Ok(h) => {
                self.error = Some(format!("Hops must be <= {MAX_HOPS}, got {h}"));
                return None;
            }
            _ => {
                self.error = Some("Hops must be 3\u{2013}10".to_string());
                return None;
            }
        };

        let max_rebuild_attempts: usize = match self.max_rebuild_attempts.parse() {
            Ok(a) if a >= 1 => a,
            _ => {
                self.error = Some("Max rebuild attempts must be >= 1".to_string());
                return None;
            }
        };

        self.error = None;
        Some(TorClientConfig {
            socks_addr: self.socks_addr.clone(),
            directory_url: self.directory_url.clone(),
            pool_size,
            hops,
            tui: true,
            max_rebuild_attempts,
        })
    }
}

pub fn run_wizard(defaults: &TorClientConfig) -> Result<TorClientConfig> {
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
    defaults: &TorClientConfig,
) -> Result<TorClientConfig> {
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
            KeyCode::Backspace => state.pop_char(),
            KeyCode::Enter => {
                if let Some(config) = state.validate() {
                    return Ok(config);
                }
            }
            KeyCode::Char(c) => {
                state.push_char(c);
            }
            _ => {}
        }
    }
}

fn render(frame: &mut Frame, state: &WizardState) {
    let area = frame.area();

    let vertical = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(FIELDS.len() as u16 + 2),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    let title_area = vertical.first().copied().unwrap_or(area);
    let fields_area = vertical.get(1).copied().unwrap_or(area);
    let status_area = vertical.get(2).copied().unwrap_or(area);
    let help_area = vertical.get(3).copied().unwrap_or(area);

    let title = Paragraph::new(" Tor Client Setup \u{2014} Configure, then press Enter to launch")
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, title_area);

    let rows: Vec<Line> = FIELDS
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

            let text = match field {
                Field::SocksAddr => state.socks_addr.as_str(),
                Field::DirectoryUrl => state.directory_url.as_str(),
                Field::PoolSize => state.pool_size.as_str(),
                Field::Hops => state.hops.as_str(),
                Field::MaxRebuildAttempts => state.max_rebuild_attempts.as_str(),
            };

            let cursor = if is_focused { "\u{2588}" } else { "" };
            let value_style = if is_focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };

            Line::from(vec![
                Span::styled(prefix.to_string(), label_style),
                Span::styled(format!("{:<20}", field.label()), label_style),
                Span::styled(text.to_string(), value_style),
                Span::styled(cursor.to_string(), Style::default().fg(Color::Yellow)),
            ])
        })
        .collect();

    let fields_widget = Paragraph::new(rows).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Configuration "),
    );
    frame.render_widget(fields_widget, fields_area);

    let status_text = match &state.error {
        Some(err) => Line::from(vec![
            Span::styled(
                "\u{2717} ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(err.clone(), Style::default().fg(Color::Red)),
        ]),
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

    let help = Paragraph::new(
        "\u{2191}\u{2193}/Tab move   Type edit   Backspace   Enter launch   Esc quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, help_area);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::core::config::TorClientConfig;
    use clap::Parser;

    fn make_default_config() -> TorClientConfig {
        TorClientConfig::parse_from(["tor-client"])
    }

    #[test]
    fn test_validate_valid_config() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        let config = state.validate().unwrap();
        assert_eq!(config.socks_addr, "127.0.0.1:1080");
        assert_eq!(config.hops, 3);
        assert!(config.tui);
    }

    #[test]
    fn test_validate_valid_custom_hops() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.hops = "5".to_string();
        let config = state.validate().unwrap();
        assert_eq!(config.hops, 5);
    }

    #[test]
    fn test_validate_invalid_socks_addr() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.socks_addr = "not-an-address".to_string();
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
    fn test_validate_zero_pool_size() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.pool_size = "0".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_hops_below_minimum() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.hops = "2".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_hops_above_maximum() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.hops = "11".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn test_validate_zero_rebuild_attempts() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        state.max_rebuild_attempts = "0".to_string();
        assert!(state.validate().is_none());
        assert!(state.error.is_some());
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
    fn test_validate_sets_tui_flag() {
        let defaults = make_default_config();
        let mut state = WizardState::new(&defaults);
        let config = state.validate().unwrap();
        assert!(config.tui);
    }
}
