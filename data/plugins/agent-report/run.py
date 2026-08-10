#!/usr/bin/env python3
"""
ENDGAME plugin: agent-report
Generates a structured inventory report of all agents.
"""
import json, sys
from datetime import datetime, timezone

def main():
    raw = sys.stdin.readline()
    try:
        req = json.loads(raw)
    except Exception as e:
        emit_error(req={}, msg=f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "agent-report")
    ctx       = req.get("host_context") or {}
    agents    = ctx.get("agents") or []

    now = datetime.now(timezone.utc)
    findings = []
    entities  = []

    active = [a for a in agents if a.get("active")]
    dead   = [a for a in agents if not a.get("active")]
    admins = [a for a in active if a.get("is_admin")]

    # one entity per active agent
    for a in agents:
        props = {
            "hostname":  a.get("hostname", ""),
            "username":  a.get("username", ""),
            "os":        a.get("os", ""),
            "transport": a.get("transport", ""),
            "language":  a.get("language", ""),
            "active":    str(a.get("active", False)),
            "is_admin":  str(a.get("is_admin", False)),
        }
        entities.append({
            "id":       a.get("id", ""),
            "type":     "agent",
            "name":     f"{a.get('username','')}@{a.get('hostname','')}",
            "provider": "endgame",
            "props":    props,
        })

    # high-value findings
    if admins:
        findings.append({
            "id":          "high-priv-agents",
            "title":       f"{len(admins)} admin/SYSTEM agent(s) active",
            "severity":    "info",
            "description": "The following agents are running with elevated privileges: "
                           + ", ".join(f"{a.get('username')}@{a.get('hostname')}" for a in admins),
            "entity_ids":  [a.get("id","") for a in admins],
        })

    if dead:
        findings.append({
            "id":          "dead-agents",
            "title":       f"{len(dead)} agent(s) no longer beaconing",
            "severity":    "low",
            "description": "These agents have not checked in recently: "
                           + ", ".join(f"{a.get('username')}@{a.get('hostname')}" for a in dead),
            "entity_ids":  [a.get("id","") for a in dead],
        })

    summary = (
        f"{len(active)} active agent(s), {len(dead)} dead · "
        f"{len(admins)} with admin/SYSTEM · report generated {now.strftime('%Y-%m-%d %H:%M UTC')}"
    )

    result = {
        "schema_version": 1,
        "module_id":      module_id,
        "summary":        summary,
        "findings":       findings,
        "entities":       entities,
        "metadata":       {
            "total":  str(len(agents)),
            "active": str(len(active)),
            "dead":   str(len(dead)),
            "admins": str(len(admins)),
        },
    }

    resp = {
        "protocol_version": 1,
        "run_id":   run_id,
        "module_id": module_id,
        "ok":       True,
        "result":   result,
    }
    print(json.dumps(resp))

def emit_error(req, msg):
    print(json.dumps({
        "protocol_version": 1,
        "run_id":    req.get("run_id", ""),
        "module_id": req.get("module_id", "agent-report"),
        "ok":        False,
        "error":     msg,
    }))

if __name__ == "__main__":
    main()
