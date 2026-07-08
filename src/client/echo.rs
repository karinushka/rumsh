use crate::client::terminal::TerminalFrame;
use crate::protocol::{CompactGrapheme, LocalCellData};
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredictionEntry {
    pub seq_num: u64,
    pub bytes: Vec<u8>,
    pub epoch: u64,
    pub old_cursor_x: u16,
    pub old_cursor_y: u16,
    pub old_cells: Vec<(u16, u16, LocalCellData)>,
}

#[derive(Debug, Default)]
pub struct LocalEchoEngine {
    pub unconfirmed_inputs: VecDeque<PredictionEntry>,
    pub current_epoch: u64,
}

impl LocalEchoEngine {
    pub fn new() -> Self {
        Self {
            unconfirmed_inputs: VecDeque::new(),
            current_epoch: 0,
        }
    }

    pub fn apply_keystrokes(&mut self, frame: &mut TerminalFrame, bytes: &[u8], seq_num: u64) {
        let old_cursor_x = frame.cursor_x;
        let old_cursor_y = frame.cursor_y;
        let mut old_cells = Vec::new();

        for &b in bytes {
            match b {
                b'\r' => {
                    frame.cursor_x = 0;
                }
                b'\n' => {
                    frame.cursor_x = 0;
                    frame.cursor_y = (frame.cursor_y + 1).min(frame.rows.saturating_sub(1));
                }
                0x08 | 0x7f => {
                    // Backspace / Delete
                    if frame.cursor_x > 0 {
                        frame.cursor_x -= 1;
                        let x = frame.cursor_x;
                        let y = frame.cursor_y;
                        if x < frame.cols && y < frame.rows {
                            let idx = (y as usize) * (frame.cols as usize) + (x as usize);
                            if !old_cells.iter().any(|(ox, oy, _)| *ox == x && *oy == y) {
                                old_cells.push((x, y, frame.cell_cache[idx]));
                            }
                            frame.cell_cache[idx] = LocalCellData {
                                graphemes: CompactGrapheme::new(" "),
                                fg: None,
                                bg: None,
                                style_flags: 0,
                            };
                        }
                    }
                }
                _ => {
                    // Printable ASCII or UTF-8 byte
                    if (0x20..0x7f).contains(&b) {
                        let x = frame.cursor_x;
                        let y = frame.cursor_y;
                        if x < frame.cols && y < frame.rows {
                            let idx = (y as usize) * (frame.cols as usize) + (x as usize);
                            if !old_cells.iter().any(|(ox, oy, _)| *ox == x && *oy == y) {
                                old_cells.push((x, y, frame.cell_cache[idx]));
                            }
                            let ch = (b as char).to_string();
                            frame.cell_cache[idx] = LocalCellData {
                                graphemes: CompactGrapheme::new(&ch),
                                fg: None,
                                bg: None,
                                style_flags: 0,
                            };
                            frame.cursor_x += 1;
                            if frame.cursor_x >= frame.cols {
                                frame.cursor_x = 0;
                                frame.cursor_y =
                                    (frame.cursor_y + 1).min(frame.rows.saturating_sub(1));
                            }
                        }
                    }
                }
            }
        }

        self.unconfirmed_inputs.push_back(PredictionEntry {
            seq_num,
            bytes: bytes.to_vec(),
            epoch: self.current_epoch,
            old_cursor_x,
            old_cursor_y,
            old_cells,
        });
    }

    pub fn reconcile_frame(&mut self, frame: &mut TerminalFrame, ack_seq: u64) {
        while let Some(front) = self.unconfirmed_inputs.front() {
            if front.seq_num <= ack_seq || front.epoch < self.current_epoch {
                self.unconfirmed_inputs.pop_front();
            } else {
                break;
            }
        }

        if !self.unconfirmed_inputs.is_empty() {
            let surviving: Vec<PredictionEntry> = self.unconfirmed_inputs.drain(..).collect();
            for entry in surviving {
                self.apply_keystrokes(frame, &entry.bytes, entry.seq_num);
            }
        }
    }

    pub fn abort(&mut self, frame: &mut TerminalFrame) {
        for entry in self.unconfirmed_inputs.iter().rev() {
            frame.cursor_x = entry.old_cursor_x;
            frame.cursor_y = entry.old_cursor_y;
            for &(x, y, cell) in entry.old_cells.iter().rev() {
                if x < frame.cols && y < frame.rows {
                    let idx = (y as usize) * (frame.cols as usize) + (x as usize);
                    frame.cell_cache[idx] = cell;
                }
            }
        }
        self.unconfirmed_inputs.clear();
        self.current_epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_engine_apply_and_reconcile() {
        let mut frame = TerminalFrame::new(80, 24);
        let mut engine = LocalEchoEngine::new();

        // Type "abc" (seq 1)
        engine.apply_keystrokes(&mut frame, b"abc", 1);
        assert_eq!(frame.cursor_x, 3);
        assert_eq!(frame.cell_cache[0].graphemes.as_str(), "a");
        assert_eq!(frame.cell_cache[1].graphemes.as_str(), "b");
        assert_eq!(frame.cell_cache[2].graphemes.as_str(), "c");
        assert_eq!(engine.unconfirmed_inputs.len(), 1);

        // Type "d" (seq 2)
        engine.apply_keystrokes(&mut frame, b"d", 2);
        assert_eq!(frame.cursor_x, 4);
        assert_eq!(engine.unconfirmed_inputs.len(), 2);

        // Server frame arrives acknowledging seq 1 ("abc")!
        let mut server_frame = TerminalFrame::new(80, 24);
        server_frame.cursor_x = 3;
        server_frame.cell_cache[0].graphemes = CompactGrapheme::new("a");
        server_frame.cell_cache[1].graphemes = CompactGrapheme::new("b");
        server_frame.cell_cache[2].graphemes = CompactGrapheme::new("c");

        engine.reconcile_frame(&mut server_frame, 1);
        assert_eq!(server_frame.cursor_x, 4);
        assert_eq!(server_frame.cell_cache[3].graphemes.as_str(), "d");
        assert_eq!(engine.unconfirmed_inputs.len(), 1);
        assert_eq!(engine.unconfirmed_inputs[0].seq_num, 2);
    }

    #[test]
    fn test_echo_engine_abort_rollback() {
        let mut frame = TerminalFrame::new(80, 24);
        let mut engine = LocalEchoEngine::new();

        engine.apply_keystrokes(&mut frame, b"xyz", 1);
        assert_eq!(frame.cursor_x, 3);
        assert_eq!(frame.cell_cache[0].graphemes.as_str(), "x");
        assert_eq!(engine.unconfirmed_inputs.len(), 1);

        engine.abort(&mut frame);
        assert_eq!(frame.cursor_x, 0);
        assert_eq!(frame.cell_cache[0].graphemes.as_str(), " ");
        assert_eq!(engine.unconfirmed_inputs.len(), 0);
        assert_eq!(engine.current_epoch, 1);
    }

    #[test]
    fn test_echo_engine_backspace_and_newline() {
        let mut frame = TerminalFrame::new(80, 24);
        let mut engine = LocalEchoEngine::new();

        engine.apply_keystrokes(&mut frame, b"a\nb\x08", 1);
        assert_eq!(frame.cursor_x, 0);
        assert_eq!(frame.cursor_y, 1);
        assert_eq!(frame.cell_cache[0].graphemes.as_str(), "a");
        assert_eq!(frame.cell_cache[80].graphemes.as_str(), " ");
    }
}
