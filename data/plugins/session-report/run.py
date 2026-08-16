#!/usr/bin/env python3
"""
ENDGAME plugin: session-report

Produces a comprehensive operation report exportable as HTML/PDF/CSV.

Inspired by:
  - CobaltStrike's built-in reporting (Activity Report, Indicators of Compromise, Sessions Report)
  - Mythic's operation summary dashboard
  - Havoc community reporting plugins

Sections:
  1. Operation overview — agent count, host count, domain coverage, timespan
  2. Agent inventory — each agent with privilege, transport, sleep, last seen
  3. Privilege map — SYSTEM/admin vs user-level footholds per host
  4. Transport diversity — breakdown by protocol and language
  5. BloodHound coverage — node/edge stats, high-value objects found
  6. Domain privilege findings — DA members, unconstrained delegation, ASREP, Kerberoast
"""
import json, sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

HIGH_VALUE_GROUPS = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "ACCOUNT OPERATORS", "BACKUP OPERATORS",
    "PRINT OPERATORS", "SERVER OPERATORS", "GROUP POLICY CREATOR OWNERS",
}


def normalize(name: str) -> str:
    n = (name or "").strip().upper()
    if "\\" in n:
        return n.split("\\", 1)[1]
    if "@" in n:
        return n.split("@")[0]
    return n


def fmt_dt(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso


def time_ago(iso: str) -> str:
    if not iso:
        return "unknown"
    try:
        dt  = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        sec = int((datetime.now(timezone.utc) - dt).total_seconds())
        if sec < 120:   return f"{sec}s ago"
        if sec < 3600:  return f"{sec//60}m ago"
        if sec < 86400: return f"{sec//3600}h ago"
        return f"{sec//86400}d ago"
    except Exception:
        return iso


def emit(run_id, module_id, ok, summary="", findings=None,
         entities=None, relationships=None, metadata=None, error=""):
    out = {"protocol_version": 1, "run_id": run_id, "module_id": module_id, "ok": ok}
    if error:
        out["error"] = error
    if ok:
        out["result"] = {
            "schema_version": 1,
            "module_id": module_id,
            "summary": summary,
            "findings": findings or [],
            "entities": entities or [],
            "relationships": relationships or [],
            "metadata": metadata or {},
        }
    print(json.dumps(out))


def main():
    try:
        req = json.loads(sys.stdin.readline())
    except Exception as e:
        emit("", "session-report", False, error=f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "session-report")
    ctx       = req.get("host_context") or {}
    agents    = ctx.get("agents") or []
    graph     = ctx.get("graph") or {}
    nodes     = graph.get("nodes") or []
    edges     = graph.get("edges") or []
    now       = datetime.now(timezone.utc)

    # ── Agent stats ───────────────────────────────────────────────────────────
    active      = [a for a in agents if a.get("active")]
    dead        = [a for a in agents if not a.get("active")]
    admin_agents = [a for a in active if a.get("is_admin")]

    by_host = defaultdict(list)
    for a in active:
        by_host[a.get("hostname", "?")].append(a)

    by_transport = defaultdict(int)
    by_language  = defaultdict(int)
    for a in active:
        by_transport[(a.get("transport") or "unknown").lower()] += 1
        by_language[(a.get("language")  or "unknown").lower()] += 1

    # Earliest first_seen across all agents
    first_seen = None
    for a in agents:
        fs = a.get("first_seen")
        if not fs:
            continue
        try:
            dt = datetime.fromisoformat(fs.replace("Z", "+00:00"))
            if first_seen is None or dt < first_seen:
                first_seen = dt
        except Exception:
            pass

    # ── BloodHound graph stats ────────────────────────────────────────────────
    by_type = defaultdict(int)
    for n in nodes:
        by_type[n.get("type", "unknown")] += 1

    edge_types = defaultdict(int)
    for e in edges:
        edge_types[e.get("edge_type", "?")]  += 1

    # Unconstrained delegation computers
    uncons_deleg = []
    kerb_users   = []
    asrep_users  = []
    da_members   = []   # users in high-value groups

    member_of = defaultdict(set)
    for e in edges:
        if e["edge_type"] == "MemberOf":
            member_of[e["source_sid"]].add(e["target_sid"])

    # SID → group name for high-value groups
    hv_group_sids = set()
    for n in nodes:
        if n.get("type", "").lower() == "group":
            gname = normalize(n.get("name", ""))
            # strip domain prefix if present (e.g. "DOMAIN ADMINS@NORTH...")
            base = gname.split("@")[0].strip()
            if base in HIGH_VALUE_GROUPS:
                hv_group_sids.add(n["sid"])

    for n in nodes:
        ntype = n.get("type", "").lower()
        try:
            props = json.loads(n.get("props") or "{}")
        except Exception:
            props = {}

        if ntype == "computer":
            if props.get("unconstraineddelegation") or props.get("unconstrained_delegation"):
                uncons_deleg.append(n.get("name", ""))

        if ntype == "user":
            if props.get("enabled") is False or props.get("enabled") == "False":
                continue
            if props.get("hasspn") or props.get("has_spn"):
                kerb_users.append(n.get("name", ""))
            if props.get("dontreqpreauth") or props.get("dont_req_preauth"):
                asrep_users.append(n.get("name", ""))
            # DA membership
            user_groups = member_of.get(n["sid"], set())
            if user_groups & hv_group_sids:
                da_members.append(n.get("name", ""))

    # ── Findings ──────────────────────────────────────────────────────────────
    findings = []

    # Section 1: Operation overview
    op_duration = ""
    if first_seen:
        delta = now - first_seen
        hours = int(delta.total_seconds() // 3600)
        op_duration = f"{hours}h" if hours < 48 else f"{hours//24}d"

    overview_lines = [
        f"  Generated   : {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Op started  : {fmt_dt(first_seen.isoformat() if first_seen else '')}",
        f"  Duration    : {op_duration or '—'}",
        f"  Active agents : {len(active)}",
        f"  Dead agents   : {len(dead)}",
        f"  Compromised hosts : {len(by_host)}",
        f"  Admin/SYSTEM footholds : {len(admin_agents)} / {len(active)}",
        f"  Transports   : {', '.join(f'{k}={v}' for k, v in sorted(by_transport.items()))}",
        f"  Languages    : {', '.join(f'{k}={v}' for k, v in sorted(by_language.items()))}",
    ]
    if nodes:
        overview_lines += [
            f"  BH nodes  : {len(nodes)} "
            f"(users={by_type.get('user',0)}, computers={by_type.get('computer',0)}, "
            f"groups={by_type.get('group',0)}, domains={by_type.get('domain',0)})",
            f"  BH edges  : {len(edges)}",
        ]
    findings.append({
        "id": "operation-overview",
        "title": "Operation Overview",
        "severity": "info",
        "description": "\n".join(overview_lines),
    })

    # Section 2: Compromised host map
    if by_host:
        host_lines = []
        for host in sorted(by_host):
            host_agents = by_host[host]
            admin_flag  = "🔴" if any(a.get("is_admin") for a in host_agents) else "🔵"
            transports  = ", ".join(sorted({a.get("transport","?") for a in host_agents}))
            users       = ", ".join(sorted({a.get("username","?") for a in host_agents}))
            host_lines.append(f"  {admin_flag} {host:<30}  users={users}  transport={transports}")
        findings.append({
            "id": "compromised-hosts",
            "title": f"Compromised hosts — {len(by_host)} host(s)",
            "severity": "info",
            "description": "🔴=SYSTEM/admin  🔵=user\n\n" + "\n".join(host_lines),
            "evidence": "\n".join(host_lines),
        })

    # Section 3: Privilege map
    system_hosts = sorted(h for h, lst in by_host.items() if any(a.get("is_admin") for a in lst))
    user_hosts   = sorted(h for h, lst in by_host.items() if not any(a.get("is_admin") for a in lst))
    priv_lines   = []
    if system_hosts:
        priv_lines.append("SYSTEM / Admin:")
        priv_lines += [f"  ✓ {h}" for h in system_hosts]
    if user_hosts:
        priv_lines.append("User-level only (escalation needed):")
        priv_lines += [f"  ✗ {h}" for h in user_hosts]
    if priv_lines:
        findings.append({
            "id": "privilege-map",
            "title": f"Privilege map — {len(system_hosts)} admin host(s), {len(user_hosts)} user-level",
            "severity": "critical" if system_hosts else "medium",
            "description": "\n".join(priv_lines),
        })

    # Section 4: BloodHound high-value findings
    if da_members:
        findings.append({
            "id": "da-members",
            "title": f"{len(da_members)} user(s) in high-value group(s) (Domain Admins, etc.)",
            "severity": "critical",
            "description": "High-value group members found in BloodHound data:\n"
                         + "\n".join(f"  • {u}" for u in sorted(da_members)[:30]),
            "evidence": "\n".join(sorted(da_members)[:30]),
        })

    if uncons_deleg:
        findings.append({
            "id": "unconstrained-delegation",
            "title": f"{len(uncons_deleg)} computer(s) with unconstrained delegation",
            "severity": "high",
            "description": "Unconstrained delegation hosts cache TGTs of connecting users — "
                           "if you control the machine account you can extract tickets.\n"
                         + "\n".join(f"  • {c}" for c in sorted(uncons_deleg)[:20]),
            "remediation": "Use printer bug / SpoolSample to coerce DC TGT to these hosts, then extract with Rubeus.",
        })

    if kerb_users:
        findings.append({
            "id": "kerberoastable",
            "title": f"{len(kerb_users)} Kerberoastable user(s)",
            "severity": "high",
            "description": "Users with SPNs — request their TGS and crack offline.\n"
                         + "\n".join(f"  • {u}" for u in sorted(kerb_users)[:30]),
            "remediation": "Use impacket-GetUserSPNs or Rubeus kerberoast to extract and crack.",
        })

    if asrep_users:
        findings.append({
            "id": "asrep-roastable",
            "title": f"{len(asrep_users)} AS-REP roastable user(s)",
            "severity": "high",
            "description": "Users without pre-auth required — request AS-REP and crack offline.\n"
                         + "\n".join(f"  • {u}" for u in sorted(asrep_users)[:30]),
            "remediation": "Use impacket-GetNPUsers or Rubeus asreproast to extract and crack.",
        })

    # Section 5: Agent inventory table (as a finding with evidence)
    agent_table = []
    agent_table.append(f"  {'ID':<10} {'HOST':<22} {'USER':<30} {'PRIV':<8} {'TRANSPORT':<8} {'SLEEP':<8} {'LAST SEEN'}")
    agent_table.append("  " + "-"*105)
    for a in sorted(active, key=lambda x: (x.get("hostname",""), x.get("username",""))):
        priv = "ADMIN" if a.get("is_admin") else "user"
        agent_table.append(
            f"  {a.get('id','')[:8]:<10} {a.get('hostname',''):<22} {a.get('username',''):<30} "
            f"{priv:<8} {(a.get('transport') or ''):<8} {str(a.get('sleep_sec',''))+'s':<8} "
            f"{time_ago(a.get('last_seen',''))}"
        )
    if dead:
        agent_table.append("")
        agent_table.append(f"  Dead agents ({len(dead)}):")
        for a in sorted(dead, key=lambda x: x.get("hostname","")):
            agent_table.append(f"  {a.get('id','')[:8]:<10} {a.get('hostname',''):<22} {a.get('username','')}")

    findings.append({
        "id": "agent-inventory",
        "title": f"Agent inventory — {len(active)} active, {len(dead)} dead",
        "severity": "info",
        "description": "Full agent roster:",
        "evidence": "\n".join(agent_table),
    })

    # ── Entities ──────────────────────────────────────────────────────────────
    entities = []

    # Agent entities
    for a in agents:
        entities.append({
            "id": a.get("id", ""),
            "type": "agent",
            "name": f"{a.get('username','')}@{a.get('hostname','')}",
            "provider": "endgame",
            "props": {
                "hostname":     a.get("hostname", ""),
                "username":     a.get("username", ""),
                "os":           a.get("os", ""),
                "transport":    a.get("transport", ""),
                "language":     a.get("language", ""),
                "sleep_sec":    str(a.get("sleep_sec", "")),
                "is_admin":     str(a.get("is_admin", False)),
                "active":       str(a.get("active", False)),
                "process_name": a.get("process_name", ""),
                "last_seen":    fmt_dt(a.get("last_seen", "")),
                "first_seen":   fmt_dt(a.get("first_seen", "")),
            },
        })

    # High-value graph entities
    for n in nodes:
        ntype = n.get("type", "").lower()
        if ntype not in ("user", "computer"):
            continue
        try:
            props = json.loads(n.get("props") or "{}")
        except Exception:
            props = {}

        flags = []
        if ntype == "user":
            if props.get("hasspn") or props.get("has_spn"):
                flags.append("kerberoastable")
            if props.get("dontreqpreauth") or props.get("dont_req_preauth"):
                flags.append("asreproastable")
            if n["sid"] in member_of and member_of[n["sid"]] & hv_group_sids:
                flags.append("domain-admin")
            if props.get("admincount"):
                flags.append("adminCount")
            if props.get("enabled") is False or str(props.get("enabled","")).lower() == "false":
                flags.append("disabled")
        if ntype == "computer":
            if props.get("unconstraineddelegation") or props.get("unconstrained_delegation"):
                flags.append("unconstrained-delegation")

        ent_props = {
            "domain":    n.get("domain", ""),
            "enabled":   str(props.get("enabled", "True")),
            "flags":     ", ".join(flags) if flags else "",
        }
        if ntype == "user":
            ent_props["description"] = str(props.get("description", ""))
            ent_props["lastLogon"]   = str(props.get("lastlogon") or props.get("lastLogon") or "")
            ent_props["adminCount"]  = str(props.get("admincount", ""))
        if ntype == "computer":
            ent_props["os"]          = str(props.get("os", ""))
            ent_props["lastLogon"]   = str(props.get("lastlogontimestamp") or "")
            ent_props["delegation"]  = str(props.get("unconstraineddelegation") or props.get("unconstrained_delegation") or False)

        entities.append({
            "id":       n["sid"],
            "type":     ntype,
            "name":     n.get("name", ""),
            "provider": "bloodhound",
            "props":    ent_props,
        })

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata = {
        "generated":          now.strftime("%Y-%m-%d %H:%M UTC"),
        "active_agents":      str(len(active)),
        "compromised_hosts":  str(len(by_host)),
        "admin_footholds":    str(len(admin_agents)),
        "bh_nodes":           str(len(nodes)),
        "bh_edges":           str(len(edges)),
        "da_accounts":        str(len(da_members)),
        "kerberoastable":     str(len(kerb_users)),
        "asrep_roastable":    str(len(asrep_users)),
        "unconstrained_deleg": str(len(uncons_deleg)),
    }
    if op_duration:
        metadata["op_duration"] = op_duration

    summary = (
        f"Session Report — {len(active)} active agent(s) on {len(by_host)} host(s) · "
        f"{len(admin_agents)} admin foothold(s) · "
        f"{len(da_members)} DA account(s) · "
        f"{len(kerb_users)} Kerberoastable"
    )
    emit(run_id, module_id, True,
         summary=summary, findings=findings, entities=entities, metadata=metadata)


if __name__ == "__main__":
    main()
