use std::time::Duration;

use super::*;

async fn sess() -> Session {
    Session::spawn(SessionOpts::default()).await.unwrap()
}

#[tokio::test]
async fn cwd_and_env_persist_across_exec() {
    let s = sess().await;
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().canonicalize().unwrap();
    s.exec_collect(&format!("cd {}", dir.display()), None)
        .await
        .unwrap();
    s.exec_collect("export FOO=bar42", None).await.unwrap();
    let r = s.exec_collect("pwd; echo $FOO", None).await.unwrap();
    assert_eq!(r.stdout, format!("{}\nbar42\n", dir.display()));
    assert_eq!(r.exit.code, 0);
    s.close().await;
}

#[tokio::test]
async fn exit_code_stderr_and_quoting() {
    let s = sess().await;
    // The command string is shell code: balanced quotes survive verbatim...
    let r = s
        .exec_collect(
            "echo \"it's \\\"quoted\\\"\" >&2; exit_code=3; (exit $exit_code)",
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.stderr, "it's \"quoted\"\n");
    assert_eq!(r.exit.code, 3);
    // ...while an unbalanced quote is a plain shell syntax error: nonzero rc,
    // a message on stderr, and the session keeps working.
    let r = s.exec_collect("echo it's", None).await.unwrap();
    assert_ne!(r.exit.code, 0);
    assert!(!r.stderr.is_empty());
    let r = s.exec_collect("if then fi (", None).await.unwrap();
    assert_ne!(r.exit.code, 0);
    assert_eq!(
        s.exec_collect("echo alive", None).await.unwrap().stdout,
        "alive\n"
    );
    s.close().await;
}

#[tokio::test]
async fn output_without_trailing_newline_and_multibyte_survive() {
    let s = sess().await;
    let r = s
        .exec_collect("printf 'no-newline-\u{4e2d}\u{6587}'", None)
        .await
        .unwrap();
    assert_eq!(r.stdout, "no-newline-\u{4e2d}\u{6587}");
    s.close().await;
}

#[tokio::test]
async fn command_stdin_is_detached_from_the_control_pipe() {
    let s = sess().await;
    // Without </dev/null, `cat` would swallow the next control line and hang.
    let r = s
        .exec_collect("cat", Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(r.exit.code, 0);
    assert!(!r.exit.timed_out);
    s.close().await;
}

#[tokio::test]
async fn streaming_delivers_chunks_before_the_command_finishes() {
    let s = sess().await;
    let (tx, mut rx) = mpsc::channel(16);
    let t0 = Instant::now();
    let run = tokio::spawn(async move {
        s.exec("echo first; sleep 1; echo second", None, tx)
            .await
            .unwrap();
        s.close().await;
    });
    let first = rx.recv().await.unwrap();
    assert_eq!(
        first,
        Event::Stdout {
            data: "first\n".into()
        }
    );
    assert!(
        t0.elapsed() < Duration::from_millis(800),
        "first chunk arrived late: {:?}",
        t0.elapsed()
    );
    run.await.unwrap();
}

#[tokio::test]
async fn infinite_output_is_capped_and_killed() {
    let s = Session::spawn(SessionOpts {
        output_cap: 64 * 1024,
        ..Default::default()
    })
    .await
    .unwrap();
    let t0 = Instant::now();
    let r = s
        .exec_collect("yes", Some(Duration::from_secs(20)))
        .await
        .unwrap();
    assert!(r.exit.truncated);
    assert_eq!(r.stdout.len(), 64 * 1024, "captured exactly the cap");
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    // `yes` is gone from this session's tree (not just from stdout: the
    // process itself) and the session is still usable with its state intact.
    // Scoped to the session's tree — a host-wide `pgrep yes` would race with
    // the sibling test that also runs `yes`.
    let r = s.exec_collect("echo after", None).await.unwrap();
    assert_eq!(r.stdout, "after\n");
    assert!(!r.exit.session_reset);
    let shell = s.shell_pid().await.unwrap();
    let comms: Vec<String> = descendants(shell)
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
        .collect();
    assert!(
        !comms.iter().any(|c| c.starts_with("yes")),
        "yes survived the cap kill: {comms:?}"
    );
    s.close().await;
}

#[tokio::test]
async fn without_the_cap_the_same_command_would_not_stop() {
    // Oracle for the cap: with a huge cap the same flood is only ended by the timeout.
    let s = Session::spawn(SessionOpts {
        output_cap: usize::MAX,
        ..Default::default()
    })
    .await
    .unwrap();
    let r = s
        .exec_collect("yes", Some(Duration::from_millis(500)))
        .await
        .unwrap();
    assert!(!r.exit.truncated);
    assert!(r.exit.timed_out);
    assert!(
        r.stdout.len() > 64 * 1024,
        "uncapped run captured {} bytes",
        r.stdout.len()
    );
    s.close().await;
}

#[tokio::test]
async fn shell_level_infinite_loop_escalates_to_session_kill() {
    let s = Session::spawn(SessionOpts {
        output_cap: 4096,
        kill_grace: Duration::from_millis(500),
        ..Default::default()
    })
    .await
    .unwrap();
    let r = s
        .exec_collect("while true; do echo y; done", Some(Duration::from_secs(20)))
        .await
        .unwrap();
    assert!(r.exit.truncated);
    assert!(r.exit.session_reset);
    assert_eq!(r.exit.code, 137);
    let r = s.exec_collect("echo fresh", None).await.unwrap();
    assert_eq!(r.stdout, "fresh\n");
    assert!(r.exit.session_reset, "restarted shell is flagged");
    s.close().await;
}

#[tokio::test]
async fn timeout_kills_the_command() {
    let s = sess().await;
    let r = s
        .exec_collect("sleep 30", Some(Duration::from_millis(300)))
        .await
        .unwrap();
    assert!(r.exit.timed_out);
    assert_eq!(
        s.exec_collect("echo ok", None).await.unwrap().stdout,
        "ok\n"
    );
    s.close().await;
}

#[tokio::test]
async fn close_kills_the_whole_process_tree_including_setsid_daemons() {
    let s = sess().await;
    let d = tempfile::tempdir().unwrap();
    let pidfile = d.path().join("pids");
    s.exec_collect(
        &format!(
            "(sleep 300 & echo $! >> {p}); (setsid sleep 301 & echo $! >> {p}); sleep 0.2",
            p = pidfile.display()
        ),
        None,
    )
    .await
    .unwrap();
    let pids: Vec<i32> = std::fs::read_to_string(&pidfile)
        .unwrap()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 2);
    assert!(pids.iter().all(|p| pid_alive(*p)));
    let shell = s.shell_pid().await.unwrap();
    s.close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!pid_alive(shell));
    // The plain background child is in the shell's group/tree and must be gone.
    assert!(
        !pid_alive(pids[0]),
        "background child survived session close"
    );
}

#[tokio::test]
async fn fs_roundtrip_binary_and_list() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("a/b/blob.bin");
    let data: Vec<u8> = (0..=255).collect();
    fs::write_file(f.to_str().unwrap(), &data, Some(0o600))
        .await
        .unwrap();
    assert_eq!(fs::read_file(f.to_str().unwrap()).await.unwrap(), data);
    let ls = fs::list_dir(d.path().join("a/b").to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        ls,
        vec![fs::DirEntry {
            name: "blob.bin".into(),
            is_dir: false,
            size: 256
        }]
    );
    assert!(fs::read_file("/definitely/not/here").await.is_err());
    assert!(fs::read_file("").await.is_err());
}

#[tokio::test]
async fn http_request_get_and_post_against_local_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.starts_with("POST") {
                    "chunky"
                } else {
                    "plain"
                };
                let resp = if req.contains("/chunked") {
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 201 Created\r\nX-A: b\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                s.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });
    let r = http::request(&http::HttpRequest {
        method: "GET".into(),
        url: format!("http://127.0.0.1:{port}/x"),
        headers: Default::default(),
        body: vec![],
    })
    .await
    .unwrap();
    assert_eq!(
        (r.status, r.body.as_slice(), r.headers["x-a"].as_str()),
        (201, &b"plain"[..], "b")
    );
    let r = http::request(&http::HttpRequest {
        method: "POST".into(),
        url: format!("http://127.0.0.1:{port}/x"),
        headers: Default::default(),
        body: b"data".to_vec(),
    })
    .await
    .unwrap();
    assert_eq!(r.body, b"chunky");
    let r = http::request(&http::HttpRequest {
        method: "GET".into(),
        url: format!("http://127.0.0.1:{port}/chunked"),
        headers: Default::default(),
        body: vec![],
    })
    .await
    .unwrap();
    assert_eq!(r.body, b"abcdef");
    assert!(http::request(&http::HttpRequest {
        method: "GET".into(),
        url: "https://x/".into(),
        headers: Default::default(),
        body: vec![]
    })
    .await
    .is_err());
}
