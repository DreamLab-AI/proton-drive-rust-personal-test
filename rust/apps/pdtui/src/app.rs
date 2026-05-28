//! TUI event loop + state.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use zeroize::Zeroizing;

use crate::auth::{self, AuthError, Credentials};
use crate::keymap::{Action, dispatch};
use crate::panes::{Focus, Panes};
use crate::session;

const BASE_URL: &str = "https://drive.proton.me/api";

// ---------------------------------------------------------------------------
// Screen state
// ---------------------------------------------------------------------------

pub enum Screen {
    Main,
    Login(LoginForm),
    Authenticating(JoinHandle<Result<Credentials, AuthError>>),
}

pub struct LoginForm {
    pub email: String,
    /// Password field. Wrapped in `Zeroizing` so the heap buffer is wiped on
    /// drop (ADR-0011). Callers use `form.password.as_str()` to read it.
    pub password: Zeroizing<String>,
    pub field: LoginField,
    pub error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LoginField {
    Email,
    Password,
}

impl LoginForm {
    pub fn new() -> Self {
        Self {
            email: String::new(),
            password: Zeroizing::new(String::new()),
            field: LoginField::Email,
            error: None,
        }
    }
}

impl Default for LoginForm {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub panes: Panes,
    pub focus: Focus,
    pub should_quit: bool,
    pub screen: Screen,
    pub status: Option<String>,
}

impl App {
    pub fn new() -> Self {
        let screen = if session::Session::load().is_ok() {
            Screen::Main
        } else {
            Screen::Login(LoginForm::new())
        };
        Self {
            panes: Panes::new(),
            focus: Focus::Local,
            should_quit: false,
            screen,
            status: None,
        }
    }

    pub async fn run(
        &mut self,
        term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> io::Result<()> {
        while !self.should_quit {
            term.draw(|frame| {
                crate::ui::render(
                    frame,
                    &self.panes,
                    self.focus,
                    &self.screen,
                    self.status.as_deref(),
                )
            })?;
            self.tick().await?;
        }
        Ok(())
    }

    async fn tick(&mut self) -> io::Result<()> {
        self.check_auth_result().await;

        if !event::poll(Duration::from_millis(100))? {
            return Ok(());
        }
        if let Event::Key(k) = event::read()? {
            if k.kind != KeyEventKind::Press {
                return Ok(());
            }
            // Use discriminant check so we can call &mut self methods without
            // holding a borrow on self.screen.
            if matches!(self.screen, Screen::Login(_)) {
                self.handle_login_key(k.code, k.modifiers);
            } else if matches!(self.screen, Screen::Authenticating(_)) {
                if k.code == KeyCode::Esc {
                    self.screen = Screen::Login(LoginForm::new());
                }
            } else {
                let action = dispatch(k.code, k.modifiers);
                debug!(?action, key = ?k.code, "key event");
                self.status = None; // clear one-shot status on any keypress
                self.apply(action);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Login form key handling
    // -----------------------------------------------------------------------

    fn handle_login_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        match code {
            KeyCode::Esc => self.screen = Screen::Main,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if let Screen::Login(form) = &mut self.screen {
                    form.field = match form.field {
                        LoginField::Email => LoginField::Password,
                        LoginField::Password => LoginField::Email,
                    };
                }
            }
            KeyCode::Enter => {
                // Advance field on first Enter; submit on second.
                let advance = matches!(
                    &self.screen,
                    Screen::Login(f) if f.field == LoginField::Email
                );
                if advance {
                    if let Screen::Login(form) = &mut self.screen {
                        form.field = LoginField::Password;
                    }
                } else {
                    self.start_auth();
                }
            }
            KeyCode::Backspace => {
                if let Screen::Login(form) = &mut self.screen {
                    match form.field {
                        LoginField::Email => {
                            form.email.pop();
                        }
                        LoginField::Password => {
                            form.password.pop();
                        }
                    }
                }
            }
            KeyCode::Char(c) if !mods.contains(KeyModifiers::CONTROL) => {
                if let Screen::Login(form) = &mut self.screen {
                    match form.field {
                        LoginField::Email => form.email.push(c),
                        LoginField::Password => form.password.push(c),
                    }
                }
            }
            _ => {}
        }
    }

    fn start_auth(&mut self) {
        // Clone credential strings before we move the screen.
        let (email, password) = match &self.screen {
            Screen::Login(form) => (form.email.clone(), form.password.clone()),
            _ => return,
        };
        let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
        let handle: JoinHandle<Result<Credentials, AuthError>> = tokio::spawn(async move {
            let http = crate::http::ReqwestHttpClient::new(BASE_URL, &app_version)
                .map_err(AuthError::Http)?;
            auth::login(&http, &email, password.as_str()).await
        });
        self.screen = Screen::Authenticating(handle);
    }

    async fn check_auth_result(&mut self) {
        // Non-borrowing check for the variant.
        let finished = match &self.screen {
            Screen::Authenticating(h) => h.is_finished(),
            _ => return,
        };
        if !finished {
            return;
        }
        // Take ownership of the handle by swapping screen to a placeholder.
        let old = std::mem::replace(&mut self.screen, Screen::Main);
        let Screen::Authenticating(handle) = old else {
            return;
        };
        match handle.await {
            Ok(Ok(creds)) => {
                let username = creds.username.clone();
                if let Err(e) = auth::save_to_keyring(&creds) {
                    warn!("keyring unavailable: {e}");
                }
                if let Err(e) = auth::write_session_file(&creds) {
                    warn!("session file write failed: {e}");
                }
                self.panes.remote.error =
                    Some("✓ authenticated — remote listing wires up in M7".into());
                self.status = Some(format!("✓ logged in as {username}"));
                self.screen = Screen::Main;
            }
            Ok(Err(e)) => {
                let mut form = LoginForm::new();
                form.error = Some(e.to_string());
                self.screen = Screen::Login(form);
            }
            Err(e) => {
                let mut form = LoginForm::new();
                form.error = Some(format!("auth task panicked: {e}"));
                self.screen = Screen::Login(form);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Main-screen actions
    // -----------------------------------------------------------------------

    fn apply(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Login => self.screen = Screen::Login(LoginForm::new()),
            Action::TogglePane => {
                self.focus = match self.focus {
                    Focus::Local => Focus::Remote,
                    Focus::Remote => Focus::Local,
                };
            }
            Action::Up => self.panes.cursor_up(self.focus),
            Action::Down => self.panes.cursor_down(self.focus),
            Action::Enter => {
                if self.focus == Focus::Remote && self.panes.remote.error.is_some() {
                    self.screen = Screen::Login(LoginForm::new());
                } else {
                    self.panes.descend(self.focus);
                }
            }
            Action::Parent => self.panes.ascend(self.focus),
            Action::Refresh => self.panes.refresh(self.focus),
            Action::Upload | Action::Download => {} // M4/M5
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
