use anyhow::Result;
use async_signal::{Signal, Signals};
use futures_lite::prelude::*;
use std::sync::Arc;

pub trait LifecycleBackend: Send + Sync + 'static {
    fn enable_raw_mode(&self) -> Result<()>;
    fn disable_raw_mode(&self) -> Result<()>;
    fn enter_alternate_screen(&self) -> Result<()>;
    fn leave_alternate_screen(&self) -> Result<()>;
    fn terminal_size(&self) -> Result<(u16, u16)>;
    fn send_sigtstp(&self) -> Result<()>;
}

#[derive(Clone, Default, Debug)]
pub struct CrosstermBackend;

impl LifecycleBackend for CrosstermBackend {
    fn enable_raw_mode(&self) -> Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(())
    }
    fn disable_raw_mode(&self) -> Result<()> {
        crossterm::terminal::disable_raw_mode()?;
        Ok(())
    }
    fn enter_alternate_screen(&self) -> Result<()> {
        let mut stdout = std::io::stdout();
        crossterm::execute!(
            stdout,
            crossterm::terminal::EnterAlternateScreen,
            crossterm::cursor::Hide,
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
        )?;
        Ok(())
    }
    fn leave_alternate_screen(&self) -> Result<()> {
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        Ok(())
    }
    fn terminal_size(&self) -> Result<(u16, u16)> {
        let (cols, rows) = crossterm::terminal::size()?;
        Ok((cols, rows))
    }
    fn send_sigtstp(&self) -> Result<()> {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTSTP);
        }
        Ok(())
    }
}

pub struct TerminalLifecycle<B: LifecycleBackend = CrosstermBackend> {
    pub backend: Arc<B>,
}

impl TerminalLifecycle<CrosstermBackend> {
    pub fn new() -> Result<(Self, u16, u16)> {
        Self::with_backend(CrosstermBackend)
    }

    pub fn query_size() -> Result<(u16, u16)> {
        CrosstermBackend.terminal_size()
    }
}

impl<B: LifecycleBackend> TerminalLifecycle<B> {
    pub fn with_backend(backend: B) -> Result<(Self, u16, u16)> {
        backend.enable_raw_mode()?;
        backend.enter_alternate_screen()?;
        let (cols, rows) = backend.terminal_size()?;
        Ok((
            Self {
                backend: Arc::new(backend),
            },
            cols,
            rows,
        ))
    }

    pub fn suspend(&self, on_resume: impl FnOnce(u16, u16)) -> Result<()> {
        let _ = self.backend.disable_raw_mode();
        let _ = self.backend.leave_alternate_screen();
        let _ = self.backend.send_sigtstp();
        let _ = self.backend.enable_raw_mode();
        let _ = self.backend.enter_alternate_screen();
        if let Ok((cols, rows)) = self.backend.terminal_size() {
            on_resume(cols, rows);
        }
        Ok(())
    }

    pub fn clear_and_resize(&self, on_resize: impl FnOnce(u16, u16)) -> Result<()> {
        let _ = self.backend.enter_alternate_screen();
        if let Ok((cols, rows)) = self.backend.terminal_size() {
            on_resize(cols, rows);
        }
        Ok(())
    }

    pub fn spawn_resize_loop(
        &self,
        mut on_resize: impl FnMut(u16, u16) + Send + 'static,
    ) -> smol::Task<()> {
        let backend = self.backend.clone();
        smol::spawn(async move {
            if let Ok(mut signals) = Signals::new([Signal::Winch]) {
                while signals.next().await.is_some() {
                    if let Ok((c, r)) = backend.terminal_size() {
                        on_resize(c, r);
                    }
                }
            }
        })
    }
}

impl<B: LifecycleBackend> Drop for TerminalLifecycle<B> {
    fn drop(&mut self) {
        let _ = self.backend.leave_alternate_screen();
        let _ = self.backend.disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeLifecycleBackend {
        raw_mode: AtomicBool,
        alt_screen: AtomicBool,
        sigtstp_count: AtomicUsize,
        size: Mutex<(u16, u16)>,
    }

    impl FakeLifecycleBackend {
        fn new(cols: u16, rows: u16) -> Self {
            Self {
                raw_mode: AtomicBool::new(false),
                alt_screen: AtomicBool::new(false),
                sigtstp_count: AtomicUsize::new(0),
                size: Mutex::new((cols, rows)),
            }
        }
    }

    impl LifecycleBackend for FakeLifecycleBackend {
        fn enable_raw_mode(&self) -> Result<()> {
            self.raw_mode.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn disable_raw_mode(&self) -> Result<()> {
            self.raw_mode.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn enter_alternate_screen(&self) -> Result<()> {
            self.alt_screen.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn leave_alternate_screen(&self) -> Result<()> {
            self.alt_screen.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn terminal_size(&self) -> Result<(u16, u16)> {
            Ok(*self.size.lock().unwrap())
        }
        fn send_sigtstp(&self) -> Result<()> {
            self.sigtstp_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_lifecycle_raii_guard() {
        let fake = FakeLifecycleBackend::new(80, 24);
        let backend_arc;
        {
            let (lifecycle, cols, rows) = TerminalLifecycle::with_backend(fake).unwrap();
            assert_eq!(cols, 80);
            assert_eq!(rows, 24);
            assert!(lifecycle.backend.raw_mode.load(Ordering::SeqCst));
            assert!(lifecycle.backend.alt_screen.load(Ordering::SeqCst));
            backend_arc = lifecycle.backend.clone();
        }
        // After lifecycle is dropped:
        assert!(!backend_arc.raw_mode.load(Ordering::SeqCst));
        assert!(!backend_arc.alt_screen.load(Ordering::SeqCst));
    }

    #[test]
    fn test_lifecycle_suspend_resumption() {
        let fake = FakeLifecycleBackend::new(80, 24);
        let (lifecycle, _, _) = TerminalLifecycle::with_backend(fake).unwrap();

        let mut resumed_size = (0, 0);
        lifecycle
            .suspend(|cols, rows| {
                resumed_size = (cols, rows);
            })
            .unwrap();

        assert_eq!(lifecycle.backend.sigtstp_count.load(Ordering::SeqCst), 1);
        assert!(lifecycle.backend.raw_mode.load(Ordering::SeqCst));
        assert!(lifecycle.backend.alt_screen.load(Ordering::SeqCst));
        assert_eq!(resumed_size, (80, 24));
    }
}
