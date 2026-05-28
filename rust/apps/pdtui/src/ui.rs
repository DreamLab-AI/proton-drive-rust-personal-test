//! Rendering — PRD §7.1 layout.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::panes::{Focus, Pane, Panes};

pub fn render(frame: &mut Frame<'_>, panes: &Panes, focus: Focus) {
    let area = frame.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, layout[0]);
    render_panes(frame, layout[1], panes, focus);
    render_status(frame, layout[2]);
    render_keybar(frame, layout[3]);
}

fn render_header(frame: &mut Frame<'_>, area: Rect) {
    let line = format!(" pdtui v{}  —  personal use", proton_drive::VERSION);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_panes(frame: &mut Frame<'_>, area: Rect, panes: &Panes, focus: Focus) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_pane(frame, cols[0], &panes.local, "LOCAL", focus == Focus::Local);
    render_pane(
        frame,
        cols[1],
        &panes.remote,
        "REMOTE",
        focus == Focus::Remote,
    );
}

fn render_pane(frame: &mut Frame<'_>, area: Rect, pane: &Pane, label: &str, focused: bool) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {label}  {} ", pane.cwd.display()));
    if focused {
        block = block.border_style(Style::default().add_modifier(Modifier::BOLD));
    }

    if let Some(err) = &pane.error {
        let body = Paragraph::new(format!("\n  {err}")).block(block);
        frame.render_widget(body, area);
        return;
    }

    let items: Vec<ListItem<'_>> = pane
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let marker = if i == pane.cursor { "▶ " } else { "  " };
            let sel = if e.selected { "*" } else { " " };
            let kind = if e.is_dir { "/" } else { " " };
            let size = e
                .size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "        -".to_owned());
            ListItem::new(Line::raw(format!(
                "{marker}{sel} {name}{kind:<1}  {size}",
                name = e.name
            )))
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

fn render_status(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Paragraph::new(" idle"), area);
}

fn render_keybar(frame: &mut Frame<'_>, area: Rect) {
    let text = " F2 upload   F3 download   F5 refresh   Tab switch   q quit ";
    frame.render_widget(Paragraph::new(text), area);
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:8.1} {}", UNITS[u])
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn formats_bytes() {
        assert!(human_bytes(0).contains("B"));
        assert!(human_bytes(512).contains("B"));
    }

    #[test]
    fn formats_kib() {
        assert!(human_bytes(2048).contains("KiB"));
    }

    #[test]
    fn formats_mib() {
        assert!(human_bytes(2 * 1024 * 1024).contains("MiB"));
    }

    #[test]
    fn formats_gib() {
        assert!(human_bytes(3 * 1024 * 1024 * 1024).contains("GiB"));
    }
}
