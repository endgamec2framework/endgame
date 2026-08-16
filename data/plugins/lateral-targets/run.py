#!/usr/bin/env python3
"""
ENDGAME plugin: lateral-targets

Identifies lateral movement targets from the BloodHound graph using
the credentials currently available via active agents.

Inspired by:
  - CobaltStrike find-system-admin-users.cna (FortyNorthSecurity)
  - Mythic's BloodHound C2 profile integration
  - Havoc community BloodHound pivot scripts

Algorithm:
  1. Map active agent usernames → BloodHound user SIDs
  2. Expand via MemberOf to include group membership
  3. Walk AdminTo / CanRDP / CanPSRemote / ExecuteDCOM edges to computers
  4. Walk HasSession edges to find computers with compromised user sessions
  5. Exclude hosts already running an agent (already owned)
  6. Rank by access method: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > HasSession
"""
import json, sys
from collections import defaultdict

LATERAL_EDGES   = {"AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM"}
SEVERITY_MAP    = {
    "AdminTo":      "critical",
    "CanPSRemote":  "high",
    "CanRDP":       "high",
    "ExecuteDCOM":  "medium",
    "HasSession":   "high",
}
PRIORITY_ORDER  = ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM"]


def normalize(name: str) -> str:
    n = (name or "").strip().upper()
    if "\\" in n:
        return n.split("\\", 1)[1]
    if "@" in n:
        return n.split("@")[0]
    return n


def emit(run_id, module_id, ok, summary="", findings=None, entities=None,
         relationships=None, metadata=None, error=""):
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
        emit("", "lateral-targets", False, error=f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "lateral-targets")
    ctx       = req.get("host_context") or {}
    agents    = ctx.get("agents") or []
    graph     = ctx.get("graph") or {}
    nodes     = graph.get("nodes") or []
    edges     = graph.get("edges") or []

    active = [a for a in agents if a.get("active")]

    if not active:
        emit(run_id, module_id, True,
             summary="No active agents — nothing to pivot from.",
             findings=[{"id": "no-agents", "title": "No active agents",
                        "severity": "info", "description": "Deploy at least one agent first."}])
        return

    if not nodes:
        emit(run_id, module_id, True,
             summary="BloodHound graph is empty — import SharpHound data first.",
             findings=[{"id": "no-graph", "title": "No BloodHound graph",
                        "severity": "info",
                        "description": "Upload a SharpHound ZIP from the BloodHound tab to enable graph analysis."}])
        return

    # ── Build graph lookups ───────────────────────────────────────────────────
    sid_to_node     = {n["sid"]: n for n in nodes}
    name_to_nodes   = defaultdict(list)
    for n in nodes:
        name_to_nodes[normalize(n.get("name", ""))].append(n)

    # ── Map agent users → owned SIDs ─────────────────────────────────────────
    owned_user_sids   = {}   # sid -> agent description
    owned_host_names  = set()

    for a in active:
        owned_host_names.add(normalize(a.get("hostname", "")))
        uname = normalize(a.get("username", ""))
        for n in name_to_nodes.get(uname, []):
            if n.get("type", "").lower() == "user":
                sid = n["sid"]
                if sid not in owned_user_sids:
                    owned_user_sids[sid] = (
                        f"{a['username']}@{a['hostname']} [{a.get('id','')[:8]}]"
                    )

    if not owned_user_sids:
        emit(run_id, module_id, True,
             summary="No agent users found in BloodHound graph — check that SharpHound data covers your targets.",
             findings=[{"id": "no-user-match", "title": "No agent users matched in graph",
                        "severity": "info",
                        "description": "Active usernames: " +
                        ", ".join(a.get("username","") for a in active)}])
        return

    # ── Expand group memberships (1 hop, transitive enough for most cases) ───
    member_of = defaultdict(set)
    for e in edges:
        if e["edge_type"] == "MemberOf":
            member_of[e["source_sid"]].add(e["target_sid"])

    # BFS expansion for groups
    owned_sids = set(owned_user_sids)
    queue = list(owned_sids)
    group_sids = set()
    while queue:
        sid = queue.pop()
        for gsid in member_of.get(sid, set()):
            if gsid not in owned_sids and gsid not in group_sids:
                group_sids.add(gsid)
                queue.append(gsid)
    all_owned = owned_sids | group_sids

    # ── Walk lateral movement edges ───────────────────────────────────────────
    # computer_sid -> {method -> source_label}
    reachable = defaultdict(dict)

    for e in edges:
        if e["edge_type"] not in LATERAL_EDGES:
            continue
        if e["source_sid"] not in all_owned:
            continue
        tgt = sid_to_node.get(e["target_sid"])
        if not tgt or tgt.get("type", "").lower() != "computer":
            continue
        src_label = (owned_user_sids.get(e["source_sid"]) or
                     f"group:{sid_to_node.get(e['source_sid'],{}).get('name','?')}")
        reachable[e["target_sid"]][e["edge_type"]] = src_label

    # ── Walk HasSession edges (computer --HasSession--> user) ─────────────────
    # computer_sid -> [user labels with sessions]
    sessions = defaultdict(list)
    for e in edges:
        if e["edge_type"] != "HasSession":
            continue
        if e["target_sid"] not in owned_user_sids:
            continue
        comp = sid_to_node.get(e["source_sid"])
        if not comp or comp.get("type", "").lower() != "computer":
            continue
        sessions[e["source_sid"]].append(owned_user_sids[e["target_sid"]])

    # ── Categorise targets ────────────────────────────────────────────────────
    def already_owned(comp_node):
        return normalize(comp_node.get("name", "")) in owned_host_names

    new_admin    = []   # (sid, node, methods)
    new_remote   = []
    owned_extra  = []
    session_hunt = []

    for sid, methods in reachable.items():
        node = sid_to_node[sid]
        entry = (sid, node, methods)
        if already_owned(node):
            owned_extra.append(entry)
        elif "AdminTo" in methods:
            new_admin.append(entry)
        else:
            new_remote.append(entry)

    for sid, users in sessions.items():
        node = sid_to_node.get(sid)
        if not node:
            continue
        if not already_owned(node) and sid not in reachable:
            session_hunt.append((sid, node, users))

    # ── Build findings ────────────────────────────────────────────────────────
    findings = []

    if new_admin:
        lines = "\n".join(
            f"  • {node.get('name','')}  via {', '.join(sorted(methods.keys()))}  "
            f"(as {next(iter(methods.values()))})"
            for _, node, methods in sorted(new_admin, key=lambda x: x[1].get("name",""))[:25]
        )
        findings.append({
            "id": "new-admin-targets",
            "title": f"{len(new_admin)} new host(s) reachable with local admin rights",
            "severity": "critical",
            "description": f"These computers accept admin connections from your current credentials. "
                           f"Deploy an agent immediately.\n\n{lines}",
            "remediation": "Use rdp-inject, shell schtasks, or nxc smb --exec to deploy an agent.",
            "evidence": lines,
        })

    if new_remote:
        lines = "\n".join(
            f"  • {node.get('name','')}  via {', '.join(sorted(methods.keys()))}"
            for _, node, methods in sorted(new_remote, key=lambda x: x[1].get("name",""))[:25]
        )
        findings.append({
            "id": "new-remote-targets",
            "title": f"{len(new_remote)} host(s) reachable via RDP / PSRemote / DCOM",
            "severity": "high",
            "description": f"These hosts allow remote access but not local admin. "
                           f"Interactive access may still allow credential theft.\n\n{lines}",
            "evidence": lines,
        })

    if session_hunt:
        lines = "\n".join(
            f"  • {node.get('name','')}  sessions: {', '.join(users[:3])}"
            for _, node, users in sorted(session_hunt, key=lambda x: x[1].get("name",""))[:25]
        )
        findings.append({
            "id": "session-targets",
            "title": f"{len(session_hunt)} host(s) have active sessions of compromised users",
            "severity": "high",
            "description": f"Compromised users have live sessions on these hosts. "
                           f"Injecting into their processes or using make-token may yield fresh credentials.\n\n{lines}",
            "remediation": "Use rdp-inject with the relevant user's credentials, or deploy an agent and run token steal.",
            "evidence": lines,
        })

    if owned_extra:
        names = ", ".join(node.get("name","") for _, node, _ in owned_extra[:10])
        findings.append({
            "id": "owned-extra-paths",
            "title": f"{len(owned_extra)} already-owned host(s) have additional lateral paths",
            "severity": "info",
            "description": f"These hosts are already compromised but offer more access methods: {names}",
        })

    if not findings:
        findings.append({
            "id": "no-targets",
            "title": "No new lateral targets found",
            "severity": "info",
            "description": (
                f"Checked {len(owned_user_sids)} owned user(s) (expanded to {len(all_owned)} SIDs "
                f"with group memberships) against {len(nodes)} nodes and {len(edges)} edges.\n"
                f"Either all reachable hosts are already compromised or the graph lacks the relevant data."
            ),
        })

    # ── Entities (new reachable computers) ───────────────────────────────────
    entities = []
    seen = set()
    for sid, node, methods in new_admin + new_remote:
        if sid in seen:
            continue
        seen.add(sid)
        props = {
            "access":   ", ".join(sorted(methods.keys())),
            "domain":   node.get("domain", ""),
            "priority": "admin" if "AdminTo" in methods else "remote",
        }
        try:
            np = json.loads(node.get("props") or "{}")
            if "os" in np:
                props["os"] = np["os"]
            if "enabled" in np:
                props["enabled"] = str(np["enabled"])
        except Exception:
            pass
        entities.append({
            "id":       sid,
            "type":     "host",
            "name":     node.get("name", ""),
            "provider": "bloodhound",
            "props":    props,
        })
    for sid, node, users in session_hunt:
        if sid in seen:
            continue
        seen.add(sid)
        entities.append({
            "id":       sid,
            "type":     "host",
            "name":     node.get("name", ""),
            "provider": "bloodhound",
            "props": {
                "access":  "HasSession",
                "domain":  node.get("domain", ""),
                "sessions": "; ".join(users[:5]),
            },
        })

    total_new = len(new_admin) + len(new_remote) + len(session_hunt)
    metadata = {
        "owned_users":    str(len(owned_user_sids)),
        "owned_sids_total": str(len(all_owned)),
        "graph_nodes":    str(len(nodes)),
        "graph_edges":    str(len(edges)),
        "new_targets":    str(total_new),
        "admin_targets":  str(len(new_admin)),
        "session_targets": str(len(session_hunt)),
    }
    summary = (
        f"Lateral analysis — {len(owned_user_sids)} owned user(s) · "
        f"{len(new_admin)} admin target(s) · {len(new_remote)} remote target(s) · "
        f"{len(session_hunt)} session target(s)"
    )
    emit(run_id, module_id, True,
         summary=summary, findings=findings, entities=entities, metadata=metadata)


if __name__ == "__main__":
    main()
