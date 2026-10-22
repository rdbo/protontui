//! A one-line text field: cursor movement, editing keys, optional masking (passwords).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::text::{Line, Span};
use zeroize::Zeroize;

use super::theme;

#[derive(Debug, Default, Clone)]
pub struct TextInput {
    value: String,
    /// In characters.
    cursor: usize,
    masked: bool,
}

impl TextInput {
    pub fn masked() -> Self {
        Self { value: String::new(), cursor: 0, masked: true }
    }

    pub fn with_value(value: &str) -> Self {
        Self { value: value.to_owned(), cursor: value.chars().count(), masked: false }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Empties the field, wiping the old contents from memory.
    pub fn clear(&mut self) {
        self.value.zeroize();
        self.cursor = 0;
    }

    /// Takes the value out, leaving the field empty.
    pub fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.value)
    }

    fn byte_index(&self, chars: usize) -> usize {
        self.value.char_indices().nth(chars).map_or(self.value.len(), |(i, _)| i)
    }

    /// Handles an editing key. Returns whether it was one (Enter, Esc, Tab and the like are not).
    pub fn handle(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let len = self.value.chars().count();
        match key.code {
            KeyCode::Char('u') if ctrl => self.clear(),
            KeyCode::Char('w') if ctrl => {
                let before: Vec<char> = self.value.chars().take(self.cursor).collect();
                let mut start = before.len();
                while start > 0 && before[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && before[start - 1] != ' ' {
                    start -= 1;
                }
                let (from, to) = (self.byte_index(start), self.byte_index(self.cursor));
                self.value.replace_range(from..to, "");
                self.cursor = start;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = len,
            KeyCode::Char(c) if !ctrl => {
                let at = self.byte_index(self.cursor);
                self.value.insert(at, c);
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let at = self.byte_index(self.cursor - 1);
                self.value.remove(at);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < len => {
                let at = self.byte_index(self.cursor);
                self.value.remove(at);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            KeyCode::Backspace | KeyCode::Delete => {}
            _ => return false,
        }
        true
    }

    /// The field as a line `width` cells wide, scrolled so the cursor shows. With `focused`, the cursor is
    /// drawn as a reversed cell.
    pub fn line(&self, width: usize, focused: bool, placeholder: &str) -> Line<'static> {
        let chars: Vec<char> = if self.masked {
            std::iter::repeat_n('•', self.value.chars().count()).collect()
        } else {
            self.value.chars().collect()
        };
        if chars.is_empty() && !focused {
            return Line::from(Span::styled(placeholder.to_owned(), theme::weak()));
        }
        let width = width.max(2);
        // A focused field needs one more cell for the cursor.
        let start = (self.cursor + usize::from(focused)).saturating_sub(width);
        let visible: String = chars.iter().skip(start).take(width).collect();
        if !focused {
            return Line::from(visible);
        }
        let cursor = self.cursor - start;
        let before: String = visible.chars().take(cursor).collect();
        let at: String = visible.chars().nth(cursor).map_or(" ".into(), String::from);
        let after: String = visible.chars().skip(cursor + 1).collect();
        Line::from(vec![
            Span::raw(before),
            Span::styled(at, ratatui::style::Style::new().add_modifier(ratatui::style::Modifier::REVERSED)),
            Span::raw(after),
        ])
    }
}

impl Drop for TextInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(input: &mut TextInput, code: KeyCode) {
        input.handle(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn edits() {
        let mut input = TextInput::default();
        for c in "héllo wörld".chars() {
            press(&mut input, KeyCode::Char(c));
        }
        press(&mut input, KeyCode::Left);
        press(&mut input, KeyCode::Backspace);
        assert_eq!(input.value(), "héllo wörd");
        press(&mut input, KeyCode::Home);
        press(&mut input, KeyCode::Delete);
        assert_eq!(input.value(), "éllo wörd");
        press(&mut input, KeyCode::End);
        input.handle(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(input.value(), "éllo ");
        assert!(!input.handle(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(input.take(), "éllo ");
        assert!(input.is_empty());
    }

    #[test]
    fn masks_and_scrolls() {
        let mut input = TextInput::masked();
        for c in "secret".chars() {
            press(&mut input, KeyCode::Char(c));
        }
        let line = input.line(4, false, "");
        assert_eq!(line.to_string(), "••••");
        let focused = input.line(4, true, "");
        assert_eq!(focused.to_string(), "••• ", "scrolled to show the cursor at the end");
        assert_eq!(TextInput::default().line(10, false, "hint").to_string(), "hint");
    }
}
