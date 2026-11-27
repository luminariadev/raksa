#![forbid(unsafe_code)]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TOKEN_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub raksa_bin: String,
    pub workspace: String,
    pub from_reports: Option<String>,
    pub siem_url: Option<String>,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            raksa_bin: default_raksa_binary().to_string(),
            workspace: ".".to_string(),
            from_reports: None,
            siem_url: None,
        }
    }
}

pub fn default_raksa_binary() -> &'static str {
    if cfg!(windows) {
        "raksa.exe"
    } else {
        "raksa"
    }
}

pub fn allocate_loopback_addr() -> io::Result<SocketAddr> {
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let listener = TcpListener::bind(bind_addr)?;
    listener.local_addr()
}

pub fn generate_session_token() -> String {
    let mut out = String::with_capacity(48);
    let pid = u64::from(std::process::id());
    for round in 0..3u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let seq = TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
        let rs = RandomState::new();
        let mut h = rs.build_hasher();
        h.write_u64(nanos);
        h.write_u64(pid);
        h.write_u64(seq);
        h.write_u64(round);
        let word = h.finish();
        out.push_str(&format!("{word:016x}"));
    }
    out
}

pub struct SidecarHandle {
    child: Child,
    addr: SocketAddr,
    token: String,
}

impl SidecarHandle {
    pub fn spawn(cfg: &SidecarConfig) -> io::Result<Self> {
        let addr = allocate_loopback_addr()?;
        let token = generate_session_token();

        let mut cmd = Command::new(&cfg.raksa_bin);
        cmd.arg("ui")
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--path")
            .arg(&cfg.workspace)
            .arg("--token-env")
            .arg("RAKSA_DESKTOP_TOKEN")
            .arg("--no-open")
            .env("RAKSA_DESKTOP_TOKEN", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        if let Some(ref reports) = cfg.from_reports {
            if !reports.trim().is_empty() {
                cmd.arg("--from-reports").arg(reports);
            }
        }
        if let Some(ref siem) = cfg.siem_url {
            if !siem.trim().is_empty() {
                cmd.arg("--siem-url").arg(siem);
            }
        }

        let child = cmd.spawn()?;
        Ok(Self { child, addr, token })
    }

    pub fn wait_ready(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("raksa sidecar exited prematurely with status {status}"),
                ));
            }
            if TcpStream::connect_timeout(&self.addr, Duration::from_millis(150)).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(80));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for raksa ui loopback listener",
        ))
    }

    pub fn launch_url(&self) -> String {
        format_launch_url(self.addr.port(), &self.token)
    }
}

impl Drop for SidecarHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn format_launch_url(port: u16, token: &str) -> String {
    format!("http://localhost:{port}/?token={token}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_loopback_port_successfully() {
        let addr = allocate_loopback_addr().expect("bind loopback ephemeral port");
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn generates_unique_hex_session_tokens() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert_eq!(a.len(), 48);
        assert_eq!(b.len(), 48);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn formats_loopback_bootstrap_url() {
        let url = format_launch_url(18787, "abc123");
        assert_eq!(url, "http://localhost:18787/?token=abc123");
    }
}
