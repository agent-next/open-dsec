//! chronus: one shell session inside a sandbox (P §3.3).
//!
//! A session owns one long-lived shell, so cwd and environment persist across
//! `exec` calls. Output streams back as it is produced. The captured output of a
//! single command is hard-capped (P §6.4: an agent running `yes` once filled the
//! host disk through unbounded log capture); on overflow the command's process
//! tree is killed and the result is marked `truncated`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, Mutex};

pub mod fs;
pub mod http;

/// Default hard cap on captured output per command (stdout + stderr).
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct SessionOpts {
    /// Shell binary; default: `bash`, falling back to `sh` (minimal images).
    pub shell: Option<String>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub output_cap: usize,
    /// After the cap/timeout kills the command's children, how long the shell
    /// may take to report before the whole session is killed (shell-level loops).
    pub kill_grace: Duration,
}

impl Default for SessionOpts {
    fn default() -> Self {
        SessionOpts { shell: None, cwd: None, env: vec![], output_cap: DEFAULT_OUTPUT_CAP, kill_grace: Duration::from_secs(2) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Stdout { data: String },
    Stderr { data: String },
    Exit(ExitInfo),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExitInfo {
    /// Exit status of the command; `-1` if the shell itself died.
    pub code: i32,
    /// Output exceeded the cap; excess was discarded and the command killed.
    pub truncated: bool,
    pub timed_out: bool,
    /// The shell was killed or died; the session was restarted fresh (cwd/env reset).
    pub session_reset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    #[serde(flatten)]
    pub exit: ExitInfo,
}

struct Shell {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<(bool, Vec<u8>)>,
    pid: i32,
}

pub struct Session {
    opts: SessionOpts,
    nonce: String,
    shell: Mutex<Option<Shell>>,
}

fn marker(nonce: &str) -> String {
    format!("\u{1f}DSEC{nonce}\u{1f}")
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Session {
    pub async fn spawn(opts: SessionOpts) -> Result<Session> {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "{:x}{:x}{:x}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let sh = Self::start_shell(&opts).await?;
        Ok(Session { opts, nonce, shell: Mutex::new(Some(sh)) })
    }

    async fn start_shell(opts: &SessionOpts) -> Result<Shell> {
        let candidates: Vec<String> = match &opts.shell {
            Some(s) => vec![s.clone()],
            None => vec!["bash".into(), "sh".into()],
        };
        let mut last = None;
        for sh in candidates {
            let mut cmd = Command::new(&sh);
            if sh.ends_with("bash") {
                cmd.args(["--noprofile", "--norc"]);
            }
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
            if let Some(c) = &opts.cwd {
                cmd.current_dir(c);
            }
            cmd.envs(opts.env.iter().cloned());
            // New session/process group: lets us kill the whole tree at once.
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            match cmd.spawn() {
                Ok(mut child) => {
                    let pid = child.id().ok_or_else(|| anyhow!("shell exited immediately"))? as i32;
                    let stdin = child.stdin.take().unwrap();
                    let (tx, rx) = mpsc::channel(64);
                    for (is_err, mut r) in [
                        (false, Box::new(child.stdout.take().unwrap()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
                        (true, Box::new(child.stderr.take().unwrap())),
                    ] {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16 * 1024];
                            loop {
                                match r.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if tx.send((is_err, buf[..n].to_vec())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    return Ok(Shell { child, stdin, rx, pid });
                }
                Err(e) => last = Some(anyhow!("spawn {sh}: {e}")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no shell")))
    }

    /// Run `cmd` in the session shell, streaming events to `tx`. The final event is
    /// always `Exit`. Calls on one session are serialized.
    pub async fn exec(&self, cmd: &str, timeout: Option<Duration>, tx: mpsc::Sender<Event>) -> Result<()> {
        let mut guard = self.shell.lock().await;
        let mut reset = false;
        if guard.is_none() {
            *guard = Some(Self::start_shell(&self.opts).await?);
            reset = true;
        }
        let sh = guard.as_mut().unwrap();
        let m = marker(&self.nonce);
        let script = format!(
            "eval {} </dev/null; __dsec_rc=$?; printf '%s%d\\n' {m} \"$__dsec_rc\"; printf '%s%d\\n' {m} \"$__dsec_rc\" >&2\n",
            shell_quote(cmd),
            m = shell_quote(&m)
        );
        let mut info = ExitInfo { session_reset: reset, ..Default::default() };
        if sh.stdin.write_all(script.as_bytes()).await.is_err() || sh.stdin.flush().await.is_err() {
            *guard = None;
            info.code = -1;
            info.session_reset = true;
            let _ = tx.send(Event::Exit(info)).await;
            return Ok(());
        }

        let mut scan = [Scan::default(), Scan::default()];
        let mut sent = 0usize;
        let cap = self.opts.output_cap;
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut killed_at: Option<Instant> = None;
        let mut shell_dead = false;
        let mut code = 0;
        while !(scan[0].done && scan[1].done) {
            let wait = match (deadline, killed_at) {
                (_, Some(k)) => (k + self.opts.kill_grace).saturating_duration_since(Instant::now()).min(Duration::from_millis(200)),
                (Some(d), None) => d.saturating_duration_since(Instant::now()),
                (None, None) => Duration::from_secs(3600),
            };
            match tokio::time::timeout(wait, sh.rx.recv()).await {
                Ok(Some((is_err, bytes))) => {
                    let s = &mut scan[is_err as usize];
                    for text in s.feed(&bytes, &m) {
                        if info.truncated {
                            continue;
                        }
                        let room = cap.saturating_sub(sent);
                        let text = if text.len() > room {
                            info.truncated = true;
                            cut_utf8(&text, room)
                        } else {
                            text
                        };
                        sent += text.len();
                        if !text.is_empty() {
                            let ev = if is_err { Event::Stderr { data: text } } else { Event::Stdout { data: text } };
                            if tx.send(ev).await.is_err() {
                                // Consumer gone: treat like a cap hit so we stop the command.
                                info.truncated = true;
                            }
                        }
                        if info.truncated && killed_at.is_none() {
                            kill_descendants(sh.pid);
                            killed_at = Some(Instant::now());
                        }
                    }
                    if !is_err {
                        if let Some(c) = scan[0].rc {
                            code = c;
                        }
                    }
                }
                Ok(None) => {
                    shell_dead = true;
                    break;
                }
                Err(_) => {
                    // Either the command timed out or the post-kill grace elapsed.
                    match killed_at {
                        None => {
                            info.timed_out = true;
                            kill_descendants(sh.pid);
                            killed_at = Some(Instant::now());
                        }
                        Some(k) if k.elapsed() >= self.opts.kill_grace => {
                            shell_dead = true;
                            break;
                        }
                        Some(_) => kill_descendants(sh.pid),
                    }
                }
            }
        }
        if shell_dead {
            kill_tree(sh.pid);
            *guard = None;
            info.code = if killed_at.is_some() { 137 } else { -1 };
            info.session_reset = true;
        } else {
            info.code = code;
        }
        let _ = tx.send(Event::Exit(info)).await;
        Ok(())
    }

    pub async fn exec_collect(&self, cmd: &str, timeout: Option<Duration>) -> Result<ExecResult> {
        let (tx, mut rx) = mpsc::channel(256);
        let run = self.exec(cmd, timeout, tx);
        let collect = async {
            let mut r = ExecResult::default();
            while let Some(ev) = rx.recv().await {
                match ev {
                    Event::Stdout { data } => r.stdout.push_str(&data),
                    Event::Stderr { data } => r.stderr.push_str(&data),
                    Event::Exit(e) => r.exit = e,
                }
            }
            r
        };
        let (res, out) = tokio::join!(run, collect);
        res?;
        Ok(out)
    }

    /// End the session: kill the shell's whole process tree (P §3.1: aether kills the
    /// chronus tree when a terminal session ends).
    pub async fn close(&self) {
        if let Some(mut sh) = self.shell.lock().await.take() {
            kill_tree(sh.pid);
            let _ = sh.child.wait().await;
        }
    }

    /// PID of the live shell (tests / diagnostics).
    pub async fn shell_pid(&self) -> Option<i32> {
        self.shell.lock().await.as_ref().map(|s| s.pid)
    }
}

/// Splits a byte stream at the end-of-command marker and yields clean UTF-8 text.
#[derive(Default)]
struct Scan {
    acc: Vec<u8>,
    done: bool,
    rc: Option<i32>,
}

impl Scan {
    fn feed(&mut self, bytes: &[u8], m: &str) -> Vec<String> {
        if self.done {
            return vec![];
        }
        self.acc.extend_from_slice(bytes);
        let mb = m.as_bytes();
        let mut out = vec![];
        if let Some(i) = find(&self.acc, mb) {
            let after = &self.acc[i + mb.len()..];
            if let Some(nl) = after.iter().position(|b| *b == b'\n') {
                self.rc = std::str::from_utf8(&after[..nl]).ok().and_then(|s| s.parse().ok());
                self.done = true;
                let head = String::from_utf8_lossy(&self.acc[..i]).into_owned();
                if !head.is_empty() {
                    out.push(head);
                }
                self.acc.clear();
            } else if i > 0 {
                // Marker seen but not its newline yet: flush what precedes it.
                let head = String::from_utf8_lossy(&self.acc[..i]).into_owned();
                out.push(head);
                self.acc.drain(..i);
            }
            return out;
        }
        // Hold back only a proper prefix of the marker (it could be split
        // across reads) and any incomplete UTF-8 tail; emit the rest at once
        // so short outputs stream immediately.
        let mut keep = (1..mb.len()).rev().find(|&k| self.acc.ends_with(&mb[..k])).unwrap_or(0);
        let safe = self.acc.len() - keep;
        if let Err(e) = std::str::from_utf8(&self.acc[..safe]) {
            if e.error_len().is_none() {
                keep += safe - e.valid_up_to();
            }
        }
        let emit = self.acc.len() - keep;
        if emit > 0 {
            out.push(String::from_utf8_lossy(&self.acc[..emit]).into_owned());
            self.acc.drain(..emit);
        }
        out
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn cut_utf8(s: &str, max: usize) -> String {
    let mut i = max.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    s[..i].to_string()
}

/// All descendants of `root` (not including it), found by scanning /proc.
fn descendants(root: i32) -> Vec<i32> {
    let mut parent_of = std::collections::HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            if let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) {
                // "pid (comm) S ppid ..." - comm may contain spaces/parens.
                if let Some(rest) = stat.rsplit_once(')').map(|x| x.1) {
                    if let Some(pp) = rest.split_whitespace().nth(1).and_then(|s| s.parse::<i32>().ok()) {
                        parent_of.insert(pid, pp);
                    }
                }
            }
        }
    }
    let mut found = vec![];
    let mut frontier = vec![root];
    while let Some(p) = frontier.pop() {
        for (&c, &pp) in &parent_of {
            if pp == p && !found.contains(&c) {
                found.push(c);
                frontier.push(c);
            }
        }
    }
    found
}

fn kill_descendants(root: i32) {
    for p in descendants(root) {
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
}

fn kill_tree(root: i32) {
    let d = descendants(root);
    unsafe { libc::kill(-root, libc::SIGKILL) };
    for p in d {
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
    unsafe { libc::kill(root, libc::SIGKILL) };
}

/// True if `pid` is alive (not a zombie).
pub fn pid_alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(')').map(|x| x.1.trim_start().starts_with(|c| c != 'Z' && c != 'X')))
        .unwrap_or(false)
}

pub(crate) fn require_abs(p: &str) -> Result<&Path> {
    let path = Path::new(p);
    if p.is_empty() {
        bail!("empty path");
    }
    Ok(path)
}

pub(crate) fn ctx<T>(r: std::io::Result<T>, what: &str) -> Result<T> {
    r.with_context(|| what.to_string())
}

#[cfg(test)]
mod tests;
