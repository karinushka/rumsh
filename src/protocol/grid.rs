use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const STYLE_BOLD: u8 = 1 << 0;
pub const STYLE_ITALIC: u8 = 1 << 1;
pub const STYLE_UNDERLINE: u8 = 1 << 2;
pub const STYLE_INVERSE: u8 = 1 << 3;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RgbColorUpdate {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactGrapheme {
    bytes: [u8; 15],
    len: u8,
}

impl CompactGrapheme {
    pub fn new(s: &str) -> Self {
        let mut bytes = [0u8; 15];
        let mut len = s.len();
        if len > 15 {
            len = 15;
            while !s.is_char_boundary(len) {
                len -= 1;
            }
        }
        bytes[..len].copy_from_slice(&s.as_bytes()[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }

    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..(self.len as usize)]) }
    }
}

impl std::fmt::Display for CompactGrapheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCellData {
    pub graphemes: CompactGrapheme,
    pub fg: Option<RgbColorUpdate>,
    pub bg: Option<RgbColorUpdate>,
    pub style_flags: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CellUpdate {
    pub x: u16,
    pub cell: LocalCellData,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RowUpdate {
    pub y: u16,
    pub cells: Vec<CellUpdate>,
    pub is_wrapped: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FrameUpdate {
    pub ref_seq: u64,
    pub cols: u16,
    pub rows: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub row_updates: Vec<RowUpdate>,
    pub is_echo_enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GridState {
    pub cols: u16,
    pub rows: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub cells: Vec<LocalCellData>,
    pub row_wrapped: Vec<bool>,
}

impl GridState {
    pub fn diff_from(
        &self,
        ref_state: Option<&GridState>,
        ref_seq: u64,
        is_echo_enabled: bool,
    ) -> FrameUpdate {
        let cols = self.cols;
        let rows = self.rows;

        let use_ref = match ref_state {
            Some(r) if r.cols == cols && r.rows == rows => Some(r),
            _ => None,
        };

        let default_cell = LocalCellData {
            graphemes: CompactGrapheme::new(" "),
            fg: None,
            bg: None,
            style_flags: 0,
        };

        let mut row_updates = Vec::new();

        for y in 0..rows {
            let mut cells = Vec::new();
            let y_idx = y as usize;

            for x in 0..cols {
                let idx = (y * cols + x) as usize;
                let to_cell = &self.cells[idx];
                let from_cell = if let Some(r) = use_ref {
                    &r.cells[idx]
                } else {
                    &default_cell
                };

                if to_cell != from_cell {
                    cells.push(CellUpdate { x, cell: *to_cell });
                }
            }

            let wrapping_changed = if let Some(r) = use_ref {
                self.row_wrapped[y_idx] != r.row_wrapped[y_idx]
            } else {
                self.row_wrapped[y_idx]
            };

            if !cells.is_empty() || wrapping_changed {
                row_updates.push(RowUpdate {
                    y,
                    cells,
                    is_wrapped: self.row_wrapped[y_idx],
                });
            }
        }

        FrameUpdate {
            ref_seq,
            cols,
            rows,
            cursor_x: self.cursor_x,
            cursor_y: self.cursor_y,
            cursor_visible: self.cursor_visible,
            row_updates,
            is_echo_enabled,
        }
    }

    pub fn patch(&mut self, diff: &FrameUpdate) -> Result<()> {
        if self.cols != diff.cols || self.rows != diff.rows {
            self.cols = diff.cols;
            self.rows = diff.rows;
            self.cells = vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                (self.cols as usize) * (self.rows as usize)
            ];
            self.row_wrapped = vec![false; self.rows as usize];
        }

        for row_update in &diff.row_updates {
            let y = row_update.y as usize;
            if y >= self.rows as usize {
                anyhow::bail!("Row update y={} out of bounds (rows={})", y, self.rows);
            }
            self.row_wrapped[y] = row_update.is_wrapped;
            for cell_update in &row_update.cells {
                let x = cell_update.x as usize;
                if x >= self.cols as usize {
                    anyhow::bail!("Cell update x={} out of bounds (cols={})", x, self.cols);
                }
                let idx = y * (self.cols as usize) + x;
                self.cells[idx] = cell_update.cell;
            }
        }

        self.cursor_x = diff.cursor_x;
        self.cursor_y = diff.cursor_y;
        self.cursor_visible = diff.cursor_visible;
        Ok(())
    }

    pub fn apply_diff(&mut self, diff: &FrameUpdate) -> Result<()> {
        self.patch(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_diff_and_patch_roundtrip() {
        let grid1 = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 0,
            cursor_y: 0,
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

        let mut grid2 = grid1.clone();
        grid2.cursor_x = 5;
        grid2.cells[10].graphemes = CompactGrapheme::new("z");
        grid2.cells[10].style_flags = STYLE_BOLD;

        let diff = grid2.diff_from(Some(&grid1), 1, true);
        assert_eq!(diff.row_updates.len(), 1);
        assert_eq!(diff.row_updates[0].cells.len(), 1);

        let mut patched = grid1.clone();
        patched.patch(&diff).unwrap();
        assert_eq!(patched, grid2);
    }

    #[test]
    fn test_grid_diff_from_none() {
        let mut grid = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 10,
            cursor_y: 5,
            cursor_visible: true,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                80 * 24
            ],
            row_wrapped: vec![false; 24],
        };
        grid.cells[0].graphemes = CompactGrapheme::new("X");

        let diff = grid.diff_from(None, 0, false);
        assert_eq!(diff.ref_seq, 0);
        assert_eq!(diff.row_updates.len(), 1);
        assert_eq!(diff.row_updates[0].cells[0].cell.graphemes.as_str(), "X");
    }

    #[test]
    fn test_grid_diff_dimension_mismatch() {
        let grid1 = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                80 * 24
            ],
            row_wrapped: vec![false; 24],
        };

        let grid2 = GridState {
            cols: 100,
            rows: 30,
            cursor_x: 5,
            cursor_y: 5,
            cursor_visible: true,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new("y"),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                100 * 30
            ],
            row_wrapped: vec![false; 30],
        };

        let diff = grid2.diff_from(Some(&grid1), 5, true);
        assert_eq!(diff.cols, 100);
        assert_eq!(diff.rows, 30);
        assert_eq!(diff.row_updates.len(), 30);

        let mut patched = grid1.clone();
        patched.patch(&diff).unwrap();
        assert_eq!(patched, grid2);
    }

    #[test]
    fn test_grid_patch_out_of_bounds_rejection() {
        let mut grid = GridState {
            cols: 80,
            rows: 24,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            cells: vec![
                LocalCellData {
                    graphemes: CompactGrapheme::new(" "),
                    fg: None,
                    bg: None,
                    style_flags: 0,
                };
                80 * 24
            ],
            row_wrapped: vec![false; 24],
        };

        let malformed_diff = FrameUpdate {
            ref_seq: 1,
            cols: 80,
            rows: 24,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            row_updates: vec![RowUpdate {
                y: 50, // OUT OF BOUNDS!
                cells: vec![],
                is_wrapped: false,
            }],
            is_echo_enabled: true,
        };

        assert!(grid.patch(&malformed_diff).is_err());
    }
}
