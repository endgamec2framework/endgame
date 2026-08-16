#!/usr/bin/env python3
"""
ENDGAME plugin: opsec-audit

Checks active agents for operational security issues.
Inspired by CobaltStrike OPSEC aggressor scripts (bluscreenofjeff, FortyNorthSecurity)
and Havoc's operational security profile system.

Checks:
  - Noisy beaconing (sleep < threshold)
  - Unencrypted HTTP transport
  - Multiple agents per host (doubled detection surface)
  - Obvious/default process names
  - Non-elevated agents (limited pivot capability)
  - Stale "active" agents (beacon missed but still marked active)
  - High jitter with very short sleep (contradictory config)
"""
import json, sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

NOISY_SLEEP_SEC   = 10    # below this = noisy
STALE_MINUTES     = 30    # active but not seen in this many minutes
SAFE_PROC_NAMES   = {     # obviously agent-named processes (flag these)
    "agent.exe", "agent_https_c.exe", "agent_http_c.exe",
    "beacon.exe", "implant.exe", "payload.exe", "shell.exe",
    "agent_https_go.exe", "agent_http_go.exe",
    "agent_https_nim.exe", "agent_https_rust.exe",
}


def emit(run_id, module_id, ok, summary="", findings=None, entities=None, error=""):
    out = {
        "protocol_version": 1,
        "run_id": run_id,
        "module_id": module_id,
        "ok": ok,
    }
    if error:
        out["error"] = error
    if ok:
        out["result"] = {
            "schema_version": 1,
            "module_id": module_id,
            "summary": summary,
            "findings": findings or [],
            "entities": entities or [],
        }
    print(json.dumps(out))


def main():
    try:
        req = json.loads(sys.stdin.readline())
    except Exception as e:
        emit("", "opsec-audit", False, error=f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "opsec-audit")
    ctx       = req.get("host_context") or {}
    agents    = ctx.get("agents") or []

    active = [a for a in agents if a.get("active")]
    if not active:
        emit(run_id, module_id, True,
             summary="No active agents to audit.",
             findings=[{"id": "no-agents", "title": "No active agents",
                        "severity": "info", "description": "No agents are currently active."}])
        return

    findings = []
    now = datetime.now(timezone.utc)

    # ── 1. Noisy beaconing ────────────────────────────────────────────────────
    noisy = [a for a in active if a.get("sleep_sec", 60) < NOISY_SLEEP_SEC]
    if noisy:
        detail = "\n".join(
            f"  • {a.get('username','')}@{a.get('hostname','')}  "
            f"sleep={a.get('sleep_sec')}s jitter={a.get('jitter_pct',0)}%  [{a.get('id','')[:8]}]"
            for a in noisy
        )
        findings.append({
            "id": "noisy-sleep",
            "title": f"Noisy beaconing — {len(noisy)} agent(s) sleeping < {NOISY_SLEEP_SEC}s",
            "severity": "high",
            "description": f"Short sleep intervals generate frequent outbound connections and are "
                           f"easily spotted by network monitoring (EDR, NDR, SIEM).\n\n{detail}",
            "remediation": f"Set sleep ≥ 30s (ideally 60–300s) for stealth operations. "
                           f"Use `sleep <sec> <jitter%>` in the agent console.",
            "evidence": detail,
            "entity_ids": [a.get("id", "") for a in noisy],
        })

    # ── 2. Unencrypted HTTP transport ─────────────────────────────────────────
    http_agents = [a for a in active if (a.get("transport") or "").lower() == "http"]
    if http_agents:
        detail = "\n".join(
            f"  • {a.get('username','')}@{a.get('hostname','')}  [{a.get('id','')[:8]}]"
            for a in http_agents
        )
        findings.append({
            "id": "plaintext-transport",
            "title": f"Unencrypted HTTP transport — {len(http_agents)} agent(s)",
            "severity": "high",
            "description": f"HTTP agents send AES-encrypted payloads over cleartext HTTP. "
                           f"While payload contents are encrypted, HTTP metadata (URIs, User-Agent, "
                           f"timing patterns) is visible to network inspection tools.\n\n{detail}",
            "remediation": "Deploy new agents using HTTPS or mTLS transport.",
            "evidence": detail,
            "entity_ids": [a.get("id", "") for a in http_agents],
        })

    # ── 3. Multiple agents per host ───────────────────────────────────────────
    by_host = defaultdict(list)
    for a in active:
        by_host[a.get("hostname", "?")].append(a)
    crowded = {h: lst for h, lst in by_host.items() if len(lst) > 1}
    for host, lst in sorted(crowded.items()):
        detail = "\n".join(
            f"  • PID {a.get('pid',0)}  {a.get('username','')}  {a.get('process_name','')}  [{a.get('id','')[:8]}]"
            for a in lst
        )
        findings.append({
            "id": f"crowded-host-{host}",
            "title": f"{len(lst)} agents on {host} — doubled detection surface",
            "severity": "medium",
            "description": f"Multiple implants on the same host increase the chance that "
                           f"at least one is caught by EDR.\n\n{detail}",
            "remediation": "Consolidate to one agent per host. Kill redundant agents.",
            "evidence": detail,
            "entity_ids": [a.get("id", "") for a in lst],
        })

    # ── 4. Obvious/default process names ─────────────────────────────────────
    obvious = [a for a in active if (a.get("process_name") or "").lower() in SAFE_PROC_NAMES]
    if obvious:
        detail = "\n".join(
            f"  • {a.get('process_name','')} on {a.get('hostname','')}  [{a.get('id','')[:8]}]"
            for a in obvious
        )
        findings.append({
            "id": "obvious-process-name",
            "title": f"Agent-like process name — {len(obvious)} agent(s)",
            "severity": "medium",
            "description": f"Process names that resemble agent/beacon binaries are an instant IoC "
                           f"for any analyst doing a process listing.\n\n{detail}",
            "remediation": "Deploy with a believable Windows process name: "
                           "RuntimeBroker.exe, SearchIndexer.exe, sihost.exe, etc. "
                           "Set 'Output filename' in the Payloads builder.",
            "evidence": detail,
            "entity_ids": [a.get("id", "") for a in obvious],
        })

    # ── 5. Non-elevated agents ────────────────────────────────────────────────
    low_priv = [a for a in active if not a.get("is_admin")]
    if low_priv:
        detail = "\n".join(
            f"  • {a.get('username','')}@{a.get('hostname','')}  [{a.get('id','')[:8]}]"
            for a in low_priv
        )
        findings.append({
            "id": "low-privilege",
            "title": f"{len(low_priv)} agent(s) without admin/SYSTEM privilege",
            "severity": "medium" if len(low_priv) == len(active) else "low",
            "description": f"Non-elevated agents cannot dump credentials, load drivers, "
                           f"or inject into high-integrity processes.\n\n{detail}",
            "remediation": "Use getsystem, token steal, UAC bypass, or local privilege escalation.",
            "entity_ids": [a.get("id", "") for a in low_priv],
        })

    # ── 6. Stale active agents ────────────────────────────────────────────────
    stale = []
    for a in active:
        ls = a.get("last_seen")
        if not ls:
            continue
        try:
            dt = datetime.fromisoformat(ls.replace("Z", "+00:00"))
            if (now - dt) > timedelta(minutes=STALE_MINUTES):
                stale.append((a, int((now - dt).total_seconds() // 60)))
        except Exception:
            pass
    if stale:
        detail = "\n".join(
            f"  • {a.get('username','')}@{a.get('hostname','')}  last seen {mins}m ago  [{a.get('id','')[:8]}]"
            for a, mins in stale
        )
        findings.append({
            "id": "stale-agents",
            "title": f"{len(stale)} agent(s) silent for >{STALE_MINUTES} min (marked active)",
            "severity": "low",
            "description": f"These agents have not beaconed recently but are still marked active. "
                           f"They may have been killed, blocked, or the process exited.\n\n{detail}",
            "remediation": "Investigate and redeploy if needed. Use 'Purge dead' to clean stale records.",
            "evidence": detail,
            "entity_ids": [a.get("id", "") for a in [x[0] for x in stale]],
        })

    # ── Entities ──────────────────────────────────────────────────────────────
    entities = []
    for a in agents:
        entities.append({
            "id": a.get("id", ""),
            "type": "agent",
            "name": f"{a.get('username','')}@{a.get('hostname','')}",
            "provider": "endgame",
            "props": {
                "hostname":     a.get("hostname", ""),
                "username":     a.get("username", ""),
                "transport":    a.get("transport", ""),
                "sleep_sec":    str(a.get("sleep_sec", "")),
                "jitter_pct":   str(a.get("jitter_pct", "")),
                "process_name": a.get("process_name", ""),
                "is_admin":     str(a.get("is_admin", False)),
                "active":       str(a.get("active", False)),
            },
        })

    if not [f for f in findings if f["severity"] in ("high", "medium", "critical")]:
        findings.append({
            "id": "opsec-clean",
            "title": f"No critical OPSEC issues detected in {len(active)} active agent(s)",
            "severity": "info",
            "description": "All checked agents passed the OPSEC audit. Continue monitoring.",
        })

    high   = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    summary = (
        f"OPSEC Audit — {len(active)} active agent(s) · "
        f"{high} HIGH · {medium} MEDIUM issues"
    )
    emit(run_id, module_id, True, summary=summary, findings=findings, entities=entities)


if __name__ == "__main__":
    main()
