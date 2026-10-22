//! Colours and shared styles. Proton's palette on the terminal's own background, so light and dark terminal
//! themes both work.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders};

/// Proton purple.
pub const PRIMARY: Color = Color::Rgb(0x6d, 0x4a, 0xff);
pub const SUCCESS: Color = Color::Rgb(0x1e, 0xa8, 0x85);
pub const WARNING: Color = Color::Rgb(0xff, 0x99, 0x00);
pub const DANGER: Color = Color::Rgb(0xdc, 0x32, 0x51);
/// Secondary text.
pub const WEAK: Color = Color::Gray;
pub const ON_COLOR: Color = Color::Rgb(0xff, 0xff, 0xff);

pub fn weak() -> Style {
    Style::new().fg(WEAK)
}

pub fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)
}

/// The highlighted row of a list.
pub fn selected() -> Style {
    Style::new().bg(PRIMARY).fg(ON_COLOR).add_modifier(Modifier::BOLD)
}

/// A keyboard key in the footer and help.
pub fn key() -> Style {
    Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)
}

/// A filled badge: white text on `color`.
pub fn pill(color: Color) -> Style {
    Style::new().bg(color).fg(ON_COLOR).add_modifier(Modifier::BOLD)
}

/// Load colour: green under 75 %, amber under 90 %, red above.
pub fn load_color(load: u8) -> Color {
    match load {
        0..75 => SUCCESS,
        75..90 => WARNING,
        _ => DANGER,
    }
}

/// A rounded panel; `focused` panels get the primary colour.
pub fn panel(title: &str, focused: bool) -> Block<'_> {
    let border = if focused { Style::new().fg(PRIMARY) } else { weak() };
    let block = Block::new().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(border);
    if title.is_empty() { block } else { block.title(format!(" {title} ")).title_style(bold()) }
}
