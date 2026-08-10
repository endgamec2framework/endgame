#!/usr/bin/env python3
"""
ENDGAME plugin: ad-analyzer
Analyzes the BloodHound graph for high-value nodes, direct admin relationships,
and common escalation paths.
"""
import json, sys

TIER0_LABELS = {"Domain Controllers", "Domain Admins", "Enterprise Admins",
                "Schema Admins", "Administrators", "KRBTGT"}

def main():
    raw = sys.stdin.readline()
    try:
        req = json.loads(raw)
    except Exception as e:
        emit_error({}, f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "ad-analyzer")
    ctx       = req.get("host_context") or {}
    graph     = ctx.get("graph") or {}
    nodes     = graph.get("nodes") or []
    edges     = graph.get("edges") or []

    if not nodes:
        emit_error(req, "no graph data — run BloodHound ingestion first")
        return

    findings  = []
    entities  = []

    # index nodes
    node_map = {n.get("id",""): n for n in nodes}

    # find tier-0 nodes (DCs, DA groups, etc.)
    tier0 = [n for n in nodes if any(lbl in (n.get("labels") or []) for lbl in TIER0_LABELS)
             or any(lbl.lower() in (n.get("name","")).lower() for lbl in TIER0_LABELS)]

    # find AdminTo edges = direct admin paths
    admin_edges = [e for e in edges if (e.get("type","") or "").lower() == "adminto"]

    # find HasSession edges (credential exposure)
    session_edges = [e for e in edges if (e.get("type","") or "").lower() == "hassession"]

    # find DCSync capable entities (GetChangesAll on domain)
    dcsync_edges = [e for e in edges if (e.get("type","") or "").lower() in ("getchangesall","getchanges")]

    # Build entities for tier-0
    for n in tier0[:20]:
        entities.append({
            "id":   n.get("id",""),
            "type": "ad-object",
            "name": n.get("name",""),
            "props": {"labels": ",".join(n.get("labels") or [])},
        })

    if tier0:
        findings.append({
            "id":          "tier0-nodes",
            "title":       f"{len(tier0)} Tier-0 AD object(s) found",
            "severity":    "critical",
            "description": "High-value targets: " + ", ".join(n.get("name","") for n in tier0[:10]),
            "entity_ids":  [n.get("id","") for n in tier0[:10]],
        })

    if admin_edges:
        findings.append({
            "id":          "direct-admin-paths",
            "title":       f"{len(admin_edges)} direct AdminTo relationship(s)",
            "severity":    "high",
            "description": "Entities with direct local admin access to other hosts. "
                           "First 5: " + "; ".join(
                               f"{node_map.get(e.get('source',{}),'').get('name','?')} → "
                               f"{node_map.get(e.get('target',{}),'').get('name','?')}"
                               for e in admin_edges[:5]
                           ),
        })

    if dcsync_edges:
        findings.append({
            "id":          "dcsync-capable",
            "title":       f"{len(dcsync_edges)} entity(ies) with DCSync rights",
            "severity":    "critical",
            "description": "These principals can replicate domain secrets (DCSync): "
                           + ", ".join(node_map.get(e.get("source",""),{}).get("name","?")
                                       for e in dcsync_edges[:10]),
        })

    if session_edges:
        findings.append({
            "id":          "credential-exposure",
            "title":       f"{len(session_edges)} active session(s) expose credentials",
            "severity":    "high",
            "description": "Sessions found on hosts — lateral movement opportunity via token theft.",
        })

    summary = (
        f"{len(nodes)} nodes, {len(edges)} edges · "
        f"{len(tier0)} tier-0 objects · "
        f"{len(admin_edges)} direct admin paths · "
        f"{len(dcsync_edges)} DCSync capable"
    )

    result = {
        "schema_version": 1,
        "module_id":      module_id,
        "summary":        summary,
        "findings":       findings,
        "entities":       entities,
        "metadata": {
            "nodes":         str(len(nodes)),
            "edges":         str(len(edges)),
            "tier0":         str(len(tier0)),
            "admin_edges":   str(len(admin_edges)),
            "dcsync_edges":  str(len(dcsync_edges)),
            "session_edges": str(len(session_edges)),
        },
    }

    print(json.dumps({
        "protocol_version": 1,
        "run_id":    run_id,
        "module_id": module_id,
        "ok":        True,
        "result":    result,
    }))

def emit_error(req, msg):
    print(json.dumps({
        "protocol_version": 1,
        "run_id":    req.get("run_id", ""),
        "module_id": req.get("module_id", "ad-analyzer"),
        "ok":        False,
        "error":     msg,
    }))

if __name__ == "__main__":
    main()
