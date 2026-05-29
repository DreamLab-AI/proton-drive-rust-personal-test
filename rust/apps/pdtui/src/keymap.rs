//! Key bindings (PRD §7.4).

use crossterm::event::{KeyCode, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Login,
    TogglePane,
    Up,
    Down,
    Enter,
    Parent,
    Refresh,
    Upload,
    Download,
    Help,
    ToggleSelect,
}

pub fn dispatch(code: KeyCode, mods: KeyModifiers) -> Action {
    use KeyCode::*;
    match code {
        Char('q') => Action::Quit,
        Char('c') if mods.contains(KeyModifiers::CONTROL) => Action::Quit,
        F(4) | Char('L') => Action::Login,
        Tab | BackTab => Action::TogglePane,
        Up | Char('k') => Action::Up,
        Down | Char('j') => Action::Down,
        Enter | Char('l') => Action::Enter,
        Backspace | Char('h') => Action::Parent,
        F(5) | Char('r') => Action::Refresh,
        F(3) | Char('u') => Action::Upload,
        F(2) | Char('d') => Action::Download,
        Char('?') => Action::Help,
        Char(' ') => Action::ToggleSelect,
        _ => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};

    #[test]
    fn q_quits() {
        assert_eq!(
            dispatch(KeyCode::Char('q'), KeyModifiers::NONE),
            Action::Quit
        );
    }

    #[test]
    fn ctrl_c_quits() {
        assert_eq!(
            dispatch(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit
        );
    }

    #[test]
    fn plain_c_does_not_quit() {
        assert_eq!(
            dispatch(KeyCode::Char('c'), KeyModifiers::NONE),
            Action::None
        );
    }

    #[test]
    fn vim_keys_and_arrows_match() {
        assert_eq!(
            dispatch(KeyCode::Char('j'), KeyModifiers::NONE),
            Action::Down
        );
        assert_eq!(dispatch(KeyCode::Down, KeyModifiers::NONE), Action::Down);
        assert_eq!(dispatch(KeyCode::Char('k'), KeyModifiers::NONE), Action::Up);
        assert_eq!(dispatch(KeyCode::Up, KeyModifiers::NONE), Action::Up);
    }

    #[test]
    fn function_keys_dispatch_transfers() {
        // Domain-model-mvp.md §Cross-context flows: F3=upload, F2=download.
        assert_eq!(dispatch(KeyCode::F(3), KeyModifiers::NONE), Action::Upload);
        assert_eq!(
            dispatch(KeyCode::F(2), KeyModifiers::NONE),
            Action::Download
        );
        assert_eq!(dispatch(KeyCode::F(5), KeyModifiers::NONE), Action::Refresh);
    }

    #[test]
    fn tab_toggles_pane() {
        assert_eq!(
            dispatch(KeyCode::Tab, KeyModifiers::NONE),
            Action::TogglePane
        );
        assert_eq!(
            dispatch(KeyCode::BackTab, KeyModifiers::SHIFT),
            Action::TogglePane
        );
    }
}
