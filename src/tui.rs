use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
};
use std::io;
use tokio::sync::mpsc;
use std::time::Duration;

use crate::alerts::{Alert, AlertStore, Severity};

pub enum TuiEvent {
    Alert(Alert),
    Tick,
    Quit,
}

pub struct App {
    pub alert_store: AlertStore,
    pub selected_tab: usize,
    pub should_quit: bool,
    pub tab_titles: Vec<String>,
}

impl App {
    pub fn new() -> Self {
        Self {
            alert_store: AlertStore::new(500),
            selected_tab: 0,
            should_quit: false,
            tab_titles: vec![
                "Alerts".into(),
                "Network".into(),
                "Falco".into(),
                "FIM".into(),
                "System".into(),
            ],
        }
    }

    pub fn on_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab | KeyCode::Right => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
            }
            KeyCode::BackTab | KeyCode::Left => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
            }
            _ => {}
        }
    }
}

fn render_alerts_tab(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Alert Feed "));
    f.render_widget(list, area);
}

fn render_network_tab(f: &mut Frame, area: Rect, app: &App) {
    let network_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "network")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(network_alerts)
        .block(Block::default().borders(Borders::ALL).title(" Network Activity "));
    f.render_widget(list, area);
}

fn render_falco_tab(f: &mut Frame, area: Rect, app: &App) {
    let falco_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "falco")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(falco_alerts)
        .block(Block::default().borders(Borders::ALL).title(" Falco eBPF Alerts "));
    f.render_widget(list, area);
}

fn render_fim_tab(f: &mut Frame, area: Rect, app: &App) {
    let fim_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "samhain")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(fim_alerts)
        .block(Block::default().borders(Borders::ALL).title(" File Integrity (Samhain) "));
    f.render_widget(list, area);
}

fn render_system_tab(f: &mut Frame, area: Rect, app: &App) {
    let info_count = app.alert_store.count_by_severity(&Severity::Info);
    let warn_count = app.alert_store.count_by_severity(&Severity::Warning);
    let crit_count = app.alert_store.count_by_severity(&Severity::Critical);

    let text = vec![
        Line::from(vec![
            Span::styled("ClawAV v0.1.0", Style::default().fg(Color::Cyan).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled("ACTIVE", Style::default().fg(Color::Green).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  ℹ️  Info:     {}", info_count), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled(format!("  ⚠️  Warnings: {}", warn_count), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(format!("  🔴 Critical: {}", crit_count), Style::default().fg(Color::Red)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::raw(" to switch panels, "),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::raw(" to quit"),
        ]),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" System Status "));
    f.render_widget(paragraph, area);
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    // Tab bar
    let titles: Vec<Line> = app.tab_titles.iter().map(|t| Line::from(t.as_str())).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" 🛡️ ClawAV "))
        .select(app.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).bold());
    f.render_widget(tabs, chunks[0]);

    // Content area
    match app.selected_tab {
        0 => render_alerts_tab(f, chunks[1], app),
        1 => render_network_tab(f, chunks[1], app),
        2 => render_falco_tab(f, chunks[1], app),
        3 => render_fim_tab(f, chunks[1], app),
        4 => render_system_tab(f, chunks[1], app),
        _ => {}
    }
}

pub async fn run_tui(mut alert_rx: mpsc::Receiver<Alert>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        // Check for keyboard events (non-blocking)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key.code);
                }
            }
        }

        // Drain alert channel
        while let Ok(alert) = alert_rx.try_recv() {
            app.alert_store.push(alert);
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
