use anyhow::Result;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

struct ProcessCache {
    last_pgrp: i32,
    last_name: Option<String>,
}

pub trait PtyBackend: Send + 'static {
    fn write(&self, data: &[u8]) -> Result<()>;
    fn resize(&self, cols: u16, rows: u16) -> Result<()>;
    fn is_echo_recommended(&self) -> bool;
}

pub struct PtyBridge {
    master: Box<dyn MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn portable_pty::Child + Send>,
    foreground_cache: Mutex<ProcessCache>,
}

impl PtyBackend for PtyBridge {
    fn write(&self, data: &[u8]) -> Result<()> {
        self.write(data)
    }
    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.resize(cols, rows)
    }
    fn is_echo_recommended(&self) -> bool {
        self.is_echo_recommended()
    }
}

impl PtyBridge {
    pub fn new(
        cols: u16,
        rows: u16,
        shell_cmd: &str,
    ) -> Result<(Self, smol::channel::Receiver<Vec<u8>>)> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let parts: Vec<&str> = shell_cmd.split_whitespace().collect();
        eprintln!("DEBUG PTY PARTS: {:?}", parts);
        if parts.is_empty() {
            return Err(anyhow::anyhow!("Empty shell command"));
        }
        let mut cmd = CommandBuilder::new(parts[0]);
        for arg in &parts[1..] {
            cmd.arg(arg);
        }
        cmd.env("TERM", "xterm-256color");
        let child = pair.slave.spawn_command(cmd)?;

        // Drop the slave end of the pty to avoid leaks
        drop(pair.slave);

        let master = pair.master;
        let writer = Arc::new(Mutex::new(master.take_writer()?));

        let mut reader = master.try_clone_reader()?;
        let (tx, rx) = smol::channel::unbounded();

        // Spawn blocking reader thread
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if tx.try_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let foreground_cache = Mutex::new(ProcessCache {
            last_pgrp: -1,
            last_name: None,
        });

        Ok((
            Self {
                master,
                writer,
                child,
                foreground_cache,
            },
            rx,
        ))
    }

    pub fn write(&self, data: &[u8]) -> Result<()> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("Mutex lock poisoned"))?;
        w.write_all(data)?;
        w.flush()?;
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        Ok(())
    }

    pub fn is_echo_enabled(&self) -> bool {
        #[cfg(unix)]
        {
            if let Some(fd) = self.as_raw_fd_helper() {
                unsafe {
                    let mut termios: libc::termios = std::mem::zeroed();
                    if libc::tcgetattr(fd, &mut termios) == 0 {
                        let enabled = (termios.c_lflag & libc::ECHO) != 0;
                        log::trace!("[PTY] tcgetattr ECHO enabled={}", enabled);
                        return enabled;
                    }
                }
            }
        }
        true
    }

    #[cfg(unix)]
    pub fn get_foreground_process_name(&self) -> Option<String> {
        if let Some(fd) = self.as_raw_fd_helper() {
            unsafe {
                let pgrp = libc::tcgetpgrp(fd);
                if pgrp > 0 {
                    let mut cache = self.foreground_cache.lock().unwrap();
                    if cache.last_pgrp == pgrp {
                        return cache.last_name.clone();
                    }

                    // Cache miss: query /proc
                    cache.last_pgrp = pgrp;
                    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pgrp)) {
                        let name = Some(comm.trim().to_string());
                        cache.last_name = name.clone();
                        log::debug!(
                            "[PTY] Foreground process cache miss: pgrp={}, name={:?}",
                            pgrp,
                            name
                        );
                        return name;
                    } else {
                        cache.last_name = None;
                    }
                }
            }
        }
        None
    }

    pub fn is_echo_recommended(&self) -> bool {
        if self.is_echo_enabled() {
            return true;
        }

        #[cfg(unix)]
        {
            if let Some(proc_name) = self.get_foreground_process_name() {
                let shells = ["bash", "zsh", "sh", "fish", "rumsh"];
                let recommended = shells.contains(&proc_name.as_str());
                log::trace!(
                    "[PTY] Foreground process: '{}', local echo recommended={}",
                    proc_name,
                    recommended
                );
                return recommended;
            }
        }

        false
    }

    #[cfg(unix)]
    fn as_raw_fd_helper(&self) -> Option<std::os::unix::io::RawFd> {
        self.master.as_raw_fd()
    }
}

impl Drop for PtyBridge {
    fn drop(&mut self) {
        log::info!("Tearing down PtyBridge. Force killing shell child process.");
        if let Err(e) = self.child.kill() {
            log::debug!("Child process already dead or failed to kill: {:?}", e);
        }
    }
}

#[cfg(test)]
pub struct FakePty {
    pub written: Mutex<Vec<Vec<u8>>>,
    pub resized: Mutex<Vec<(u16, u16)>>,
    pub echo_recommended: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl FakePty {
    pub fn new() -> Self {
        Self {
            written: Mutex::new(Vec::new()),
            resized: Mutex::new(Vec::new()),
            echo_recommended: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
impl PtyBackend for FakePty {
    fn write(&self, data: &[u8]) -> Result<()> {
        self.written.lock().unwrap().push(data.to_vec());
        Ok(())
    }
    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.resized.lock().unwrap().push((cols, rows));
        Ok(())
    }
    fn is_echo_recommended(&self) -> bool {
        self.echo_recommended.load(std::sync::atomic::Ordering::Relaxed)
    }
}
