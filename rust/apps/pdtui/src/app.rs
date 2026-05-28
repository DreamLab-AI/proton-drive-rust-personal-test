//! TUI event loop + state.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tracing::debug;

use crate::keymap::{Action, dispatch};
use crate::panes::{Focus, Panes};

pub struct App {
    panes: Panes,
    focus: Focus,
    should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            panes: Panes::new(),
            focus: Focus::Local,
            should_quit: false,
        }
    }

    pub async fn run(
        &mut self,
        term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> io::Result<()> {
        while !self.should_quit {
            term.draw(|frame| crate::ui::render(frame, &self.panes, self.focus))?;
            self.tick().await?;
        }
        Ok(())
    }

    async fn tick(&mut self) -> io::Result<()> {
        if !event::poll(Duration::from_millis(100))? {
            return Ok(());
        }
        match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                let action = dispatch(k.code, k.modifiers);
                debug!(?action, key = ?k.code, "key event");
                self.apply(action);
            }
            Event::Resize(_, _) => {} // ratatui redraws on next tick
            _ => {}
        }
        Ok(())
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::TogglePane => {
                self.focus = match self.focus {
                    Focus::Local => Focus::Remote,
                    Focus::Remote => Focus::Local,
                };
            }
            Action::Up => self.panes.cursor_up(self.focus),
            Action::Down => self.panes.cursor_down(self.focus),
            Action::Enter => self.panes.descend(self.focus),
            Action::Parent => self.panes.ascend(self.focus),
            Action::Refresh => self.panes.refresh(self.focus),
            Action::Upload | Action::Download => {
                // Transfer kick-off — pending M4/M5.
            }
            Action::Help | Action::None => {}
            Action::ToggleSelect => self.panes.toggle_select(self.focus),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Suppress unused-import lint while these helpers are still skeleton.
#[allow(dead_code)]
fn _key_modifiers_used(code: KeyCode) -> bool {
    !matches!(code, KeyCode::Null)
}
