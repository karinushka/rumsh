use anyhow::{Result, anyhow};
use std::io::BufRead;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::{Command, Stdio};

pub struct SessionBootstrapper {
    remote_binary: String,
    port_range: String,
    remote_bind: Option<String>,
    remote_log_file: Option<String>,
}

impl SessionBootstrapper {
    pub fn new(
        remote_binary: String,
        port_range: String,
        remote_bind: Option<String>,
        remote_log_file: Option<String>,
    ) -> Self {
        Self {
            remote_binary,
            port_range,
            remote_bind,
            remote_log_file,
        }
    }

    /// Executes SSH to bootstrap the remote server, parses the connection token,
    /// waits for the process to detach, and resolves the DNS coordinates.
    pub fn bootstrap(&self, target_str: &str) -> Result<(SocketAddr, [u8; 32])> {
        log::info!(
            "Starting Rumsh Client in SSH Bootstrap mode for target: {}",
            target_str
        );

        let host = extract_host_from_ssh_target(target_str);

        let bind_arg = if let Some(ref ip) = self.remote_bind {
            format!(" --bind {}", ip)
        } else {
            "".to_string()
        };

        let log_arg = if let Some(ref log_file) = self.remote_log_file {
            format!(" --log-file {}", log_file)
        } else {
            "".to_string()
        };

        let remote_cmd = format!(
            "{} server --port-range {}{}{}",
            self.remote_binary, self.port_range, bind_arg, log_arg
        );
        log::info!(
            "Executing remote SSH command: ssh -o ExitOnForwardFailure=yes {} \"{}\"",
            target_str,
            remote_cmd
        );

        let mut child = Command::new("ssh")
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg(target_str)
            .arg(&remote_cmd)
            .stdout(Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture SSH stdout"))?;
        let reader = std::io::BufReader::new(stdout);

        let (port, key_str) = self.parse_token(reader)?;
        let key_bytes = parse_hex_key(&key_str)?;

        log::info!("Waiting for SSH bootstrap process to detach...");
        let status = child.wait()?;
        if !status.success() {
            return Err(anyhow!(
                "SSH bootstrap process exited with error status: {}",
                status
            ));
        }
        log::info!("SSH detached successfully.");

        let connect_host = if let Some(ref ip) = self.remote_bind {
            ip.as_str()
        } else {
            host
        };

        let resolved_addr = format!("{}:{}", connect_host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("Failed to resolve remote host: {}", connect_host))?;

        Ok((resolved_addr, key_bytes))
    }

    /// Pure, testable stream parser.
    fn parse_token<R: BufRead>(&self, reader: R) -> Result<(u16, String)> {
        for line in reader.lines() {
            let line = line?;
            log::debug!("SSH stdout: {}", line);
            if line.starts_with("RUMSH CONNECT ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 4 {
                    let port = parts[2].parse::<u16>()?;
                    let key = parts[3].to_string();
                    return Ok((port, key));
                }
            }
        }
        Err(anyhow!("Failed to parse token from bootstrap stream"))
    }
}

/// Helper to parse a 32-byte key from its 64-character hexadecimal representation.
pub fn parse_hex_key(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(anyhow!("Key must be exactly 64 hex characters (32 bytes)"));
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        let byte_str = &s[i * 2..i * 2 + 2];
        key[i] = u8::from_str_radix(byte_str, 16)?;
    }
    Ok(key)
}

/// Helper to extract the hostname from an SSH target string (e.g. user@host -> host).
fn extract_host_from_ssh_target(target: &str) -> &str {
    if let Some(idx) = target.find('@') {
        &target[idx + 1..]
    } else {
        target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_token_success() {
        let bootstrapper =
            SessionBootstrapper::new("rumsh".to_string(), "60000:61000".to_string(), None, None);
        let input = "noise\nRUMSH CONNECT 60001 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\nmore noise";
        let reader = Cursor::new(input);

        let (port, key) = bootstrapper.parse_token(reader).unwrap();
        assert_eq!(port, 60001);
        assert_eq!(
            key,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
    }

    #[test]
    fn test_parse_token_missing() {
        let bootstrapper =
            SessionBootstrapper::new("rumsh".to_string(), "60000:61000".to_string(), None, None);
        let input = "noise\nsome other connection message\nmore noise";
        let reader = Cursor::new(input);

        let res = bootstrapper.parse_token(reader);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            "Failed to parse token from bootstrap stream"
        );
    }

    #[test]
    fn test_parse_token_malformed() {
        let bootstrapper =
            SessionBootstrapper::new("rumsh".to_string(), "60000:61000".to_string(), None, None);
        let input = "RUMSH CONNECT not_a_port 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let reader = Cursor::new(input);

        let res = bootstrapper.parse_token(reader);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_hex_key() {
        let valid_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let key = parse_hex_key(valid_hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0x20);

        let invalid_len = "0102";
        assert!(parse_hex_key(invalid_len).is_err());

        let invalid_chars = "z102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert!(parse_hex_key(invalid_chars).is_err());
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host_from_ssh_target("user@myhost.com"),
            "myhost.com"
        );
        assert_eq!(extract_host_from_ssh_target("myhost.com"), "myhost.com");
    }
}
