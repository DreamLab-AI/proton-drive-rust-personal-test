//! `pdtui` — two-pane Proton Drive browser (local | remote).
//!
//! Personal use only (ADR-0007). Run from source: `cargo run -p pdtui`.
//!
//! Subcommands:
//!   pdtui            — launch the TUI
//!   pdtui probe      — run live-API diagnostic probes against the configured
//!                      session, print one JSON object per probe to stdout
//!   pdtui where      — print where the session config file should live

#![forbid(unsafe_code)]

mod app;
mod auth;
mod http;
mod keymap;
mod panes;
mod probe;
mod session;
mod transfer;
mod ui;

use std::io;
use std::process::ExitCode;
use std::sync::Arc;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    init_tracing();
    info!(version = proton_drive::VERSION, "pdtui starting");

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe") => run_probe().await,
        Some("where") => {
            println!("{}", session::Session::config_path().display());
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            print_help();
            ExitCode::from(2)
        }
        None => run_tui().await,
    }
}

fn print_help() {
    println!(
        "pdtui v{version}

USAGE:
    pdtui                 launch the TUI
    pdtui probe           run live-API diagnostic probes (M1 + M3 e2e)
    pdtui where           print where the session config file should live
    pdtui help            show this help

CONFIG:
    Session: $XDG_CONFIG_HOME/pdtui/session.json (or ~/.config/pdtui/session.json)
    Format:  {{\"AccessToken\": \"...\", \"UID\": \"...\"}}
    Logs:    set PDTUI_LOG=debug for verbose output
",
        version = proton_drive::VERSION
    );
}

async fn run_probe() -> ExitCode {
    let session = match session::Session::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "no session loaded ({e}).\n\nCreate {} containing:\n  {{\"AccessToken\": \"...\", \"UID\": \"...\"}}\n",
                session::Session::config_path().display()
            );
            return ExitCode::from(2);
        }
    };
    let client = match http::ReqwestHttpClient::new(&session.base_url, &session.app_version) {
        Ok(c) => Arc::new(c) as Arc<dyn proton_drive::ProtonDriveHttpClient>,
        Err(e) => {
            eprintln!("http client init: {e}");
            return ExitCode::FAILURE;
        }
    };
    let results = probe::run_all(client, &session).await;
    let any_fail = results.iter().any(|r| !r.ok);
    for r in &results {
        match serde_json::to_string(r) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("serialize probe result: {e}"),
        }
    }
    if any_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_tui() -> ExitCode {
    let mut term = match enter_terminal() {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "terminal setup failed");
            return ExitCode::FAILURE;
        }
    };
    let result = app::App::new().run(&mut term).await;
    if let Err(e) = leave_terminal(&mut term) {
        error!(error = %e, "terminal cleanup failed");
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pdtui exited with error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("PDTUI_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn enter_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn leave_terminal(term: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        term.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
    )?;
    term.show_cursor()?;
    Ok(())
}
