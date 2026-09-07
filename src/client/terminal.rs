use crate::client::echo::LocalEchoEngine;
use crate::protocol::{
    CompactGrapheme, GridState, LocalCellData, RgbColorUpdate, STYLE_BOLD, STYLE_INVERSE,
    STYLE_ITALIC, STYLE_UNDERLINE,
};
use anyhow::Result;
use std::io::{BufWriter, Write};
use std::sync::{Arc, RwLock};

/// A static, read-only snapshot of the terminal grid, cursor, and telemetry.
/// Used by the renderer to paint the screen.
#[derive(Clone, Debug)]
pub struct TerminalFrame {
    pub cols: u16,
    pub rows: u16,
    pub cell_cache: Vec<LocalCellData>,
    pub row_dirty: Vec<bool>,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub dirty: bool,
    pub reconnecting: bool,
    pub last_seq: u64,

    // Debugging Overlay Metrics
    pub overlay_enabled: bool,
    pub rtt_ms: u32,
    pub packet_loss_pct: f32,
    pub bandwidth_kb_s: f32,
    pub compression_ratio: f32,
    pub fps: u32,
    pub clear_requested: bool,
}

pub(crate) fn grapheme_width(g: &str) -> usize {
    if g.is_empty() {
        return 0;
    }
    let c = g.chars().next().unwrap();
    let val = c as u32;
    if (0x4e00..=0x9fff).contains(&val)
        || (0xac00..=0xd7af).contains(&val)
        || (0x3000..=0x303f).contains(&val)
        || (0x3040..=0x30ff).contains(&val)
        || (0xff00..=0xffef).contains(&val)
        || (0x1f300..=0x1f9ff).contains(&val)
    {
        2
    } else {
        1
    }
}

impl TerminalFrame {
    pub fn new(cols: u16, rows: u16) -> Self {
        let cell_cache = vec![
            LocalCellData {
                graphemes: CompactGrapheme::new(" "),
                fg: None,
                bg: None,
                style_flags: 0,
            };
            (cols as usize) * (rows as usize)
        ];
        let row_dirty = vec![true; rows as usize];

        Self {
            cols,
            rows,
            cell_cache,
            row_dirty,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            dirty: true,
            reconnecting: false,
            last_seq: 0,
            overlay_enabled: false,
            rtt_ms: 0,
            packet_loss_pct: 0.0,
            bandwidth_kb_s: 0.0,
            compression_ratio: 1.0,
            fps: 0,
            clear_requested: false,
        }
    }

    pub fn update_from_grid_state(&mut self, new_state: &GridState) -> Result<bool> {
        let mut resized = false;
        if self.cols != new_state.cols || self.rows != new_state.rows {
            self.cols = new_state.cols;
            self.rows = new_state.rows;
            self.cell_cache = vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                (self.cols as usize) * (self.rows as usize)
            ];
            self.row_dirty = vec![true; self.rows as usize];
            resized = true;
            self.clear_requested = true;
        }

        // Compare current cell_cache with new_state.cells to mark row_dirty
        for y in 0..self.rows {
            let y_idx = y as usize;
            let mut row_changed = false;
            for x in 0..self.cols {
                let idx = y_idx * (self.cols as usize) + (x as usize);
                if idx < self.cell_cache.len()
                    && idx < new_state.cells.len()
                    && self.cell_cache[idx] != new_state.cells[idx]
                {
                    row_changed = true;
                    self.cell_cache[idx] = new_state.cells[idx];
                }
            }
            if row_changed {
                self.row_dirty[y_idx] = true;
                self.dirty = true;
            }
        }

        let cursor_changed = self.cursor_x != new_state.cursor_x
            || self.cursor_y != new_state.cursor_y
            || self.cursor_visible != new_state.cursor_visible;

        if cursor_changed {
            self.cursor_x = new_state.cursor_x;
            self.cursor_y = new_state.cursor_y;
            self.cursor_visible = new_state.cursor_visible;
            self.dirty = true;
        }

        Ok(resized)
    }

    pub fn copy_to(&self, dest: &mut TerminalFrame) {
        dest.cols = self.cols;
        dest.rows = self.rows;

        if dest.cell_cache.len() != self.cell_cache.len() {
            dest.cell_cache = self.cell_cache.clone();
        } else {
            dest.cell_cache.copy_from_slice(&self.cell_cache);
        }

        if dest.row_dirty.len() != self.row_dirty.len() {
            dest.row_dirty = self.row_dirty.clone();
        } else {
            dest.row_dirty.copy_from_slice(&self.row_dirty);
        }

        dest.cursor_x = self.cursor_x;
        dest.cursor_y = self.cursor_y;
        dest.cursor_visible = self.cursor_visible;
        dest.dirty = self.dirty;
        dest.reconnecting = self.reconnecting;
        dest.last_seq = self.last_seq;
        dest.overlay_enabled = self.overlay_enabled;
        dest.rtt_ms = self.rtt_ms;
        dest.packet_loss_pct = self.packet_loss_pct;
        dest.bandwidth_kb_s = self.bandwidth_kb_s;
        dest.compression_ratio = self.compression_ratio;
        dest.fps = self.fps;
        dest.clear_requested = self.clear_requested;
    }
}

/// Internal shared state combining the passive frame and the active predictor.
#[derive(Debug)]
pub struct TerminalInner {
    pub frame: TerminalFrame,
    pub echo_engine: LocalEchoEngine,
}

/// The thread-safe handle to the Client Terminal Mirror.
/// Hides internal synchronization (Arc/RwLock) and exposes a clean behavioral interface.
#[derive(Clone, Debug)]
pub struct ClientTerminal {
    inner: Arc<RwLock<TerminalInner>>,
}

impl ClientTerminal {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            inner: Arc::new(RwLock::new(TerminalInner {
                frame: TerminalFrame::new(cols, rows),
                echo_engine: LocalEchoEngine::new(),
            })),
        }
    }

    /// Access the inner state for read-only operations in a lock block.
    /// Useful for tests.
    #[cfg(test)]
    pub fn read_inner(&self) -> std::sync::RwLockReadGuard<'_, TerminalInner> {
        self.inner.read().unwrap()
    }

    pub fn apply_frame(&self, new_state: &GridState, server_seq: u64) -> Result<bool> {
        let mut guard = self.inner.write().unwrap();
        let inner = &mut *guard;
        let resized = inner.frame.update_from_grid_state(new_state)?;
        inner.frame.last_seq = server_seq;

        // Re-apply pending predictions on top of the new server frame
        inner
            .echo_engine
            .reconcile_frame(&mut inner.frame, server_seq);

        Ok(resized)
    }

    pub fn predict_input(&self, bytes: &[u8], client_seq: u64) {
        let mut guard = self.inner.write().unwrap();
        let inner = &mut *guard;
        inner
            .echo_engine
            .apply_keystrokes(&mut inner.frame, bytes, client_seq);
    }

    pub fn acknowledge(&self, server_ack_seq: u64) {
        let mut guard = self.inner.write().unwrap();
        let inner = &mut *guard;
        inner
            .echo_engine
            .reconcile_frame(&mut inner.frame, server_ack_seq);
    }

    pub fn abort_prediction(&self) {
        let mut guard = self.inner.write().unwrap();
        let inner = &mut *guard;
        inner.echo_engine.abort(&mut inner.frame);
    }

    pub fn consume_updates(&self, dest: &mut TerminalFrame) -> bool {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        if frame.dirty || frame.clear_requested {
            frame.copy_to(dest);
            frame.dirty = false;
            let _ = &mut frame.row_dirty.fill(false);
            frame.clear_requested = false;
            true
        } else {
            false
        }
    }

    pub fn record_rtt_loss(&self, rtt_ms: Option<u32>, loss_pct: Option<f32>) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        let mut changed = false;
        if let Some(rtt) = rtt_ms {
            let new_rtt = if frame.rtt_ms == 0 {
                rtt
            } else {
                (frame.rtt_ms as f32 * 0.8 + rtt as f32 * 0.2) as u32
            };
            if frame.rtt_ms != new_rtt {
                frame.rtt_ms = new_rtt;
                changed = true;
            }
        }
        if let Some(loss) = loss_pct
            && (frame.packet_loss_pct - loss).abs() > 0.1
        {
            frame.packet_loss_pct = loss;
            changed = true;
        }
        if changed && frame.overlay_enabled {
            frame.dirty = true;
        }
    }

    pub fn record_bandwidth_compression(&self, kb_s: f32, ratio: f32) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        let bw_diff = (frame.bandwidth_kb_s - kb_s).abs();
        let cr_diff = (frame.compression_ratio - ratio).abs();
        if bw_diff > 0.1 || cr_diff > 0.1 {
            frame.bandwidth_kb_s = kb_s;
            frame.compression_ratio = ratio;
            if frame.overlay_enabled {
                frame.dirty = true;
            }
        }
    }

    pub fn record_fps(&self, fps: u32) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        if frame.fps != fps {
            frame.fps = fps;
            if frame.overlay_enabled {
                frame.dirty = true;
            }
        }
    }

    pub fn set_reconnecting(&self, reconnecting: bool) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        if frame.reconnecting != reconnecting {
            frame.reconnecting = reconnecting;
            frame.dirty = true;
            if !reconnecting {
                let y = if frame.rows > 0 { frame.rows - 1 } else { 0 };
                frame.row_dirty[y as usize] = true;
            }
        }
    }

    pub fn set_overlay_enabled(&self, enabled: bool) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        frame.overlay_enabled = enabled;
        frame.dirty = true;
    }

    pub fn toggle_overlay(&self) {
        let mut inner = self.inner.write().unwrap();
        let frame = &mut inner.frame;
        frame.overlay_enabled = !frame.overlay_enabled;
        frame.dirty = true;
    }

    pub fn rtt_ms(&self) -> u32 {
        self.inner.read().unwrap().frame.rtt_ms
    }

    pub fn mark_dirty(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.frame.dirty = true;
    }
}

pub struct ClientTerminalRenderer {
    stdout: BufWriter<std::io::Stdout>,
    pub back_buffer: TerminalFrame,
}

impl Default for ClientTerminalRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientTerminalRenderer {
    pub fn new() -> Self {
        Self {
            stdout: BufWriter::with_capacity(32 * 1024, std::io::stdout()),
            back_buffer: TerminalFrame::new(0, 0),
        }
    }

    pub fn paint(&mut self) -> Result<bool> {
        let state = &mut self.back_buffer;

        if state.clear_requested {
            state.clear_requested = false;
            crossterm::queue!(
                self.stdout,
                crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
            )?;
            self.stdout.flush()?;
        }

        if !state.dirty {
            return Ok(false);
        }
        state.dirty = false;

        let mut real_update = false;
        let (phys_cols, phys_rows) = (state.cols, state.rows);

        let mut active_style: Option<(Option<RgbColorUpdate>, Option<RgbColorUpdate>, u8)> = None;

        let apply_style = |stdout: &mut BufWriter<std::io::Stdout>,
                           style: (Option<RgbColorUpdate>, Option<RgbColorUpdate>, u8)|
         -> Result<()> {
            crossterm::queue!(
                stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;

            let (fg, bg, style_flags) = style;
            if (style_flags & STYLE_BOLD) != 0 {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetAttribute(crossterm::style::Attribute::Bold)
                )?;
            }
            if (style_flags & STYLE_ITALIC) != 0 {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetAttribute(crossterm::style::Attribute::Italic)
                )?;
            }
            if (style_flags & STYLE_UNDERLINE) != 0 {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetAttribute(crossterm::style::Attribute::Underlined)
                )?;
            }
            if (style_flags & STYLE_INVERSE) != 0 {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetAttribute(crossterm::style::Attribute::Reverse)
                )?;
            }
            if let Some(fg_color) = fg {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetForegroundColor(crossterm::style::Color::Rgb {
                        r: fg_color.r,
                        g: fg_color.g,
                        b: fg_color.b,
                    })
                )?;
            }
            if let Some(bg_color) = bg {
                crossterm::queue!(
                    stdout,
                    crossterm::style::SetBackgroundColor(crossterm::style::Color::Rgb {
                        r: bg_color.r,
                        g: bg_color.g,
                        b: bg_color.b,
                    })
                )?;
            }
            Ok(())
        };

        for y in 0..state.rows {
            let y_idx = y as usize;
            if y_idx >= phys_rows as usize {
                break;
            }
            if !state.row_dirty[y_idx] {
                continue;
            }
            state.row_dirty[y_idx] = false;
            real_update = true;

            let mut cursor_moved = false;
            let mut x = 0u16;

            while x < state.cols {
                let x_idx = x as usize;
                if x_idx >= phys_cols as usize {
                    break;
                }

                let idx = y_idx * (state.cols as usize) + x_idx;
                let cell_data = &state.cell_cache[idx];
                let width = (grapheme_width(cell_data.graphemes.as_str()) as u16).max(1);

                if x == phys_cols - 1 && y == phys_rows - 1 {
                    x += width;
                    continue;
                }

                if !cursor_moved {
                    crossterm::queue!(self.stdout, crossterm::cursor::MoveTo(x, y))?;
                    cursor_moved = true;
                }

                let current_style = (cell_data.fg, cell_data.bg, cell_data.style_flags);
                if active_style != Some(current_style) {
                    apply_style(&mut self.stdout, current_style)?;
                    active_style = Some(current_style);
                }

                let g = cell_data.graphemes.as_str();
                if !g.is_empty() {
                    self.stdout.write_all(g.as_bytes())?;
                }

                x += width;
            }
        }

        if state.reconnecting {
            let x = state.cols.saturating_sub(18);
            let y = if state.rows > 0 { state.rows - 1 } else { 0 };

            crossterm::queue!(self.stdout, crossterm::cursor::MoveTo(x, y))?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetForegroundColor(crossterm::style::Color::Red)
            )?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Bold)
            )?;
            self.stdout.write_all(b"[Reconnecting...]")?;
        }

        if state.overlay_enabled {
            let text = format!(
                " [{:>3}ms | {:>4.1}% | {:>5.1}KB/s | {:>4.1}x | {:>2}fps] ",
                state.rtt_ms,
                state.packet_loss_pct,
                state.bandwidth_kb_s,
                state.compression_ratio,
                state.fps
            );
            let len = text.len() as u16;
            let x = state.cols.saturating_sub(len);
            let y = 0;

            crossterm::queue!(self.stdout, crossterm::cursor::MoveTo(x, y))?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetForegroundColor(crossterm::style::Color::White)
            )?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetBackgroundColor(crossterm::style::Color::Rgb {
                    r: 60,
                    g: 60,
                    b: 60,
                })
            )?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Bold)
            )?;
            self.stdout.write_all(text.as_bytes())?;
            crossterm::queue!(
                self.stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;
        }

        crossterm::queue!(
            self.stdout,
            crossterm::cursor::MoveTo(state.cursor_x, state.cursor_y)
        )?;
        if state.cursor_visible {
            crossterm::queue!(self.stdout, crossterm::cursor::Show)?;
        } else {
            crossterm::queue!(self.stdout, crossterm::cursor::Hide)?;
        }

        self.stdout.flush()?;
        Ok(real_update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CompactGrapheme, GridState, LocalCellData};

    #[test]
    fn test_initialization() {
        let terminal = ClientTerminal::new(80, 24);
        let inner = terminal.read_inner();
        assert_eq!(inner.frame.cols, 80);
        assert_eq!(inner.frame.rows, 24);
        assert_eq!(inner.frame.cell_cache.len(), 80 * 24);
        assert!(inner.frame.dirty);
        assert!(inner.frame.row_dirty.iter().all(|&d| d));
    }

    #[test]
    fn test_apply_frame_and_resize() {
        let terminal = ClientTerminal::new(80, 24);

        let mut grid = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 10,
            cursor_y: 5,
            cursor_visible: true,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new("a"),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                80 * 24
            ],
            row_wrapped: vec![false; 24],
        };

        let resized = terminal.apply_frame(&grid, 1).unwrap();
        assert!(!resized);

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.frame.cursor_x, 10);
            assert_eq!(inner.frame.cursor_y, 5);
            assert!(inner.frame.cursor_visible);
            assert_eq!(inner.frame.last_seq, 1);
            assert_eq!(inner.frame.cell_cache[0].graphemes.as_str(), "a");
        }

        grid.cols = 90;
        grid.rows = 30;
        grid.cells = vec![
            LocalCellData {
                graphemes: CompactGrapheme::new("b"),
                fg: None,
                bg: None,
                style_flags: 0,
            };
            90 * 30
        ];
        grid.row_wrapped = vec![false; 30];

        let resized = terminal.apply_frame(&grid, 2).unwrap();
        assert!(resized);

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.frame.cols, 90);
            assert_eq!(inner.frame.rows, 30);
            assert_eq!(inner.frame.cell_cache.len(), 90 * 30);
            assert_eq!(inner.frame.cell_cache[0].graphemes.as_str(), "b");
            assert!(inner.frame.clear_requested);
        }
    }

    #[test]
    fn test_local_echo_and_pruning() {
        let terminal = ClientTerminal::new(80, 24);

        terminal.predict_input(b"abc", 10);

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.frame.cursor_x, 3);
            assert_eq!(inner.frame.cursor_y, 0);
            assert_eq!(inner.echo_engine.unconfirmed_inputs.len(), 1);
            assert_eq!(inner.frame.cell_cache[0].graphemes.as_str(), "a");
            assert_eq!(inner.frame.cell_cache[1].graphemes.as_str(), "b");
            assert_eq!(inner.frame.cell_cache[2].graphemes.as_str(), "c");
            assert!(inner.frame.row_dirty[0]);
        }

        let grid = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new("."),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                80 * 24
            ],
            row_wrapped: vec![false; 24],
        };

        terminal.apply_frame(&grid, 1).unwrap();

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.frame.cell_cache[0].graphemes.as_str(), "a");
            assert_eq!(inner.frame.cell_cache[1].graphemes.as_str(), "b");
            assert_eq!(inner.frame.cell_cache[2].graphemes.as_str(), "c");
            assert_eq!(inner.frame.cell_cache[3].graphemes.as_str(), ".");
        }

        terminal.acknowledge(10);

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.echo_engine.unconfirmed_inputs.len(), 0);
        }

        let mut grid2 = grid.clone();
        grid2.cells[0].graphemes = CompactGrapheme::new("x");
        grid2.cells[1].graphemes = CompactGrapheme::new("y");
        grid2.cells[2].graphemes = CompactGrapheme::new("z");

        terminal.apply_frame(&grid2, 2).unwrap();

        {
            let inner = terminal.read_inner();
            assert_eq!(inner.frame.cell_cache[0].graphemes.as_str(), "x");
            assert_eq!(inner.frame.cell_cache[1].graphemes.as_str(), "y");
            assert_eq!(inner.frame.cell_cache[2].graphemes.as_str(), "z");
        }
    }

    #[test]
    fn test_double_buffer_consumption() {
        let terminal = ClientTerminal::new(80, 24);
        let mut dest = TerminalFrame::new(80, 24);

        assert!(terminal.consume_updates(&mut dest));
        assert_eq!(dest.cols, 80);
        assert_eq!(dest.rows, 24);

        assert!(!terminal.consume_updates(&mut dest));

        terminal.set_reconnecting(true);

        assert!(terminal.consume_updates(&mut dest));
        assert!(dest.reconnecting);

        assert!(!terminal.consume_updates(&mut dest));
    }
}
