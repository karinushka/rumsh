use crate::protocol::{
    CompactGrapheme, GridState, LocalCellData, RgbColorUpdate, STYLE_BOLD, STYLE_INVERSE,
    STYLE_ITALIC, STYLE_UNDERLINE,
};
use anyhow::Result;
use libghostty_vt::render::{CellIterator, Dirty, RowIterator};
use libghostty_vt::style::Underline;
use libghostty_vt::{RenderState, Terminal, TerminalOptions};

pub struct ServerTerminalState<'cb> {
    terminal: Terminal<'static, 'cb>,
    render_state: RenderState<'static>,
    rows_iter: RowIterator<'static>,
    cells_iter: CellIterator<'static>,
    cols: u16,
    rows: u16,
    grid_state: GridState,
    force_full: bool,
}

impl<'cb> ServerTerminalState<'cb> {
    pub fn new(cols: u16, rows: u16) -> Result<Self> {
        let terminal = Terminal::new(TerminalOptions {
            cols,
            rows,
            max_scrollback: 10_000,
        })?;
        let render_state = RenderState::new()?;
        let rows_iter = RowIterator::new()?;
        let cells_iter = CellIterator::new()?;

        let cells = vec![
            LocalCellData {
                graphemes: CompactGrapheme::new(" "),
                fg: None,
                bg: None,
                style_flags: 0,
            };
            (cols as usize) * (rows as usize)
        ];
        let row_wrapped = vec![false; rows as usize];

        let grid_state = GridState {
            cols,
            rows,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            cells,
            row_wrapped,
        };

        Ok(Self {
            terminal,
            render_state,
            rows_iter,
            cells_iter,
            cols,
            rows,
            grid_state,
            force_full: true, // start with forcing full update
        })
    }

    pub fn write(&mut self, data: &[u8]) {
        self.terminal.vt_write(data);
    }

    pub fn setup_pty_callback(&mut self, mut callback: impl FnMut(&[u8]) + 'cb) -> Result<()> {
        self.terminal.on_pty_write(move |_term, data| {
            callback(data);
        })?;
        Ok(())
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.terminal.resize(cols, rows, 0, 0)?;
        self.cols = cols;
        self.rows = rows;
        self.grid_state.cols = cols;
        self.grid_state.rows = rows;
        self.grid_state.cells = vec![
            LocalCellData {
                graphemes: CompactGrapheme::new(" "),
                fg: None,
                bg: None,
                style_flags: 0,
            };
            (cols as usize) * (rows as usize)
        ];
        self.grid_state.row_wrapped = vec![false; rows as usize];
        self.force_full = true;
        Ok(())
    }

    pub fn update_and_get_state(&mut self) -> Result<&GridState> {
        let snapshot = self.render_state.update(&self.terminal)?;

        let cols = snapshot.cols()?;
        let rows = snapshot.rows()?;
        let cursor_visible = snapshot.cursor_visible()?;
        let (cursor_x, cursor_y) = if let Some(cv) = snapshot.cursor_viewport()? {
            (cv.x, cv.y)
        } else {
            (0, 0)
        };

        if self.cols != cols || self.rows != rows {
            self.cols = cols;
            self.rows = rows;
            self.grid_state.cols = cols;
            self.grid_state.rows = rows;
            self.grid_state.cells = vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                (cols as usize) * (rows as usize)
            ];
            self.grid_state.row_wrapped = vec![false; rows as usize];
            self.force_full = true;
        }

        let mut row_iter = self.rows_iter.update(&snapshot)?;
        let mut y = 0;

        while let Some(row) = row_iter.next() {
            if !self.force_full && !row.dirty()? {
                y += 1;
                continue;
            }

            let raw_row = row.raw_row()?;
            self.grid_state.row_wrapped[y] = raw_row.is_wrapped()?;

            let mut cell_iter = self.cells_iter.update(row)?;
            let mut x = 0;

            while let Some(cell) = cell_iter.next() {
                let len = cell.graphemes_len()?;
                let mut char_buf = ['\0'; 16];

                let graphemes = if len == 0 {
                    CompactGrapheme::new(" ")
                } else if len <= 16 {
                    cell.graphemes_buf(&mut char_buf[..len])?;
                    let mut byte_buf = [0u8; 64];
                    let mut offset = 0;
                    for &c in &char_buf[..len] {
                        if c == '\0' {
                            break;
                        }
                        let clean_c = if c.is_control() { ' ' } else { c };
                        let s = clean_c.encode_utf8(&mut byte_buf[offset..]);
                        offset += s.len();
                    }
                    let s = unsafe { std::str::from_utf8_unchecked(&byte_buf[..offset]) };
                    CompactGrapheme::new(s)
                } else {
                    let chars = cell.graphemes()?;
                    let mut s: String = chars.into_iter().collect();
                    if s.chars().any(|c| c.is_control()) {
                        s = s
                            .chars()
                            .map(|c| if c.is_control() { ' ' } else { c })
                            .collect();
                    }
                    CompactGrapheme::new(&s)
                };

                let fg = cell.fg_color()?.map(|c| RgbColorUpdate {
                    r: c.r,
                    g: c.g,
                    b: c.b,
                });
                let bg = cell.bg_color()?.map(|c| RgbColorUpdate {
                    r: c.r,
                    g: c.g,
                    b: c.b,
                });

                let style = cell.style()?;
                let mut style_flags = 0u8;
                if style.bold {
                    style_flags |= STYLE_BOLD;
                }
                if style.italic {
                    style_flags |= STYLE_ITALIC;
                }
                if style.inverse {
                    style_flags |= STYLE_INVERSE;
                }
                if style.underline != Underline::None {
                    style_flags |= STYLE_UNDERLINE;
                }

                let cell_data = LocalCellData {
                    graphemes,
                    fg,
                    bg,
                    style_flags,
                };

                let idx = y * (self.cols as usize) + (x as usize);
                if idx < self.grid_state.cells.len() {
                    self.grid_state.cells[idx] = cell_data;
                }
                x += 1;
            }

            // Clear row-level dirty state
            row.set_dirty(false)?;
            y += 1;
        }

        self.force_full = false;

        // Clear global dirty state using the safe, now-patched API
        snapshot.set_dirty(Dirty::Clean)?;

        self.grid_state.cursor_x = cursor_x;
        self.grid_state.cursor_y = cursor_y;
        self.grid_state.cursor_visible = cursor_visible;

        Ok(&self.grid_state)
    }
}
