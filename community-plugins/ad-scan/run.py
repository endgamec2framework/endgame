#!/usr/bin/env python3
"""
ENDGAME plugin: ad-scan
Enumerates Active Directory via LDAP: users, groups, computers,
Kerberoastable accounts (SPNs), AS-REP roastable, trusts, password policy.
"""
import json, sys
from datetime import datetime, timezone, timedelta

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print(json.dumps({
        "protocol_version": 1, "run_id": "", "module_id": "ad-scan",
        "ok": False, "error": "ldap3 not installed — pip3 install ldap3",
    }))
    sys.exit(1)

UAC_DISABLE      = 0x00000002
UAC_PASSNOREQ    = 0x00000020
UAC_NOPREAUTH    = 0x00400000
UAC_DELEGATION   = 0x00080000
UAC_NODELEG      = 0x00100000
UAC_PASSNOEXPIRE = 0x00010000

PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "print operators", "server operators", "group policy creator owners",
    "domain controllers",
}

MACHINE_SPN_PREFIXES = ("HOST/", "RestrictedKrbHost/", "TERMSRV/", "WSMAN/", "GC/")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def ldap_ts(val):
    try:
        ts = int(val)
        if ts in (0, 9223372036854775807):
            return "never"
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ts // 10)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return str(val)


def main():
    raw = sys.stdin.readline()
    try:
        req = json.loads(raw)
    except Exception as e:
        emit_error({}, f"parse request: {e}")
        return

    run_id    = req.get("run_id", "")
    module_id = req.get("module_id", "ad-scan")
    inp       = req.get("input") or {}

    dc_ip    = str(inp.get("dc_ip") or "").strip()
    domain   = str(inp.get("domain") or "").strip()
    username = str(inp.get("username") or "").strip()
    password = str(inp.get("password") or "")
    base_dn  = str(inp.get("base_dn") or "").strip()

    if not dc_ip:
        emit_error(req, "dc_ip es requerido")
        return
    if not domain:
        emit_error(req, "domain es requerido")
        return

    if not base_dn:
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))

    try:
        server = ldap3.Server(dc_ip, get_info=ldap3.ALL, port=389, connect_timeout=10)
        if username and password:
            user_str = username if "\\" in username or "@" in username else f"{domain}\\{username}"
            try:
                conn = ldap3.Connection(
                    server, user=user_str, password=password,
                    authentication=ldap3.NTLM, auto_bind=True, receive_timeout=30,
                )
            except LDAPException:
                conn = ldap3.Connection(
                    server, user=f"{username}@{domain}", password=password,
                    authentication=ldap3.SIMPLE, auto_bind=True, receive_timeout=30,
                )
        else:
            conn = ldap3.Connection(server, auto_bind=True, receive_timeout=30)
    except Exception as e:
        emit_error(req, f"LDAP connect: {e}")
        return

    findings = []
    entities = []
    metadata = {}

    try:
        # Password policy
        pwdpol = _pwdpolicy(conn, base_dn)
        metadata.update(pwdpol)
        min_len = int(pwdpol.get("minPwdLength", 7))
        lockout = int(pwdpol.get("lockoutThreshold", 0))
        if min_len < 8:
            findings.append({
                "id": "weak-pwd-length", "severity": "high",
                "title": f"Weak minimum password length: {min_len} characters",
                "description": f"Recomendado ≥ 14. Valor actual: {min_len}.",
            })
        if lockout == 0:
            findings.append({
                "id": "no-lockout", "severity": "high",
                "title": "Account lockout disabled",
                "description": "No lockout threshold — password spraying without restriction.",
            })

        # Users
        users = _users(conn, base_dn)
        enabled = [u for u in users if not u["disabled"]]
        kerb    = [u for u in enabled if u["spns"]]
        asrep   = [u for u in enabled if u["nopreauth"]]
        deleg   = [u for u in enabled if u["delegation"]]
        noexp   = [u for u in enabled if u["passnoexpire"]]
        admins  = [u for u in enabled if u["adminCount"]]

        metadata.update({
            "users_total": str(len(users)),
            "users_enabled": str(len(enabled)),
            "kerberoastable": str(len(kerb)),
            "asrep_roastable": str(len(asrep)),
            "unconstrained_delegation": str(len(deleg)),
            "admin_count": str(len(admins)),
        })

        for u in users:
            entities.append({
                "id":   f"user:{u['sam']}",
                "type": "user",
                "name": u["sam"],
                "props": {
                    "enabled":        str(not u["disabled"]),
                    "adminCount":     "1" if u["adminCount"] else "",
                    "kerberoastable": str(bool(u["spns"])),
                    "asreproastable": str(u["nopreauth"]),
                    "delegation":     str(u["delegation"]),
                    "passNoExpire":   str(u["passnoexpire"]),
                    "description":    u["description"],
                    "lastLogon":      u["lastLogon"],
                    "pwdLastSet":     u["pwdLastSet"],
                    "spns":           ", ".join(u["spns"][:3]),
                },
            })

        if kerb:
            evidence = "\n".join(f"  {u['sam']}: {', '.join(u['spns'][:2])}" for u in kerb)
            findings.append({
                "id": "kerberoastable", "severity": "high",
                "title": f"{len(kerb)} cuenta(s) Kerberoastable",
                "description": "Accounts with SPN configured — TGS hashes can be cracked offline.",
                "evidence": evidence,
                "entity_ids": [f"user:{u['sam']}" for u in kerb],
            })

        if asrep:
            findings.append({
                "id": "asrep-roastable", "severity": "high",
                "title": f"{len(asrep)} cuenta(s) AS-REP Roastable",
                "description": "DONT_REQUIRE_PREAUTH enabled — offline attack without prior credentials.",
                "evidence": "\n".join(f"  {u['sam']}" for u in asrep),
                "entity_ids": [f"user:{u['sam']}" for u in asrep],
            })

        if deleg:
            findings.append({
                "id": "unconstrained-delegation-users", "severity": "critical",
                "title": f"{len(deleg)} cuenta(s) de usuario con Unconstrained Delegation",
                "description": "Caches TGTs of all connecting users — capture = full impersonation.",
                "evidence": "\n".join(f"  {u['sam']}" for u in deleg),
            })

        if noexp:
            findings.append({
                "id": "pwd-no-expire", "severity": "medium",
                "title": f"{len(noexp)} enabled account(s) with non-expiring password",
                "description": "Passwords that never expire widen the exposure window if compromised.",
                "evidence": "\n".join(f"  {u['sam']}" for u in noexp[:20]),
            })

        # Computers
        computers = _computers(conn, base_dn)
        deleg_comp = [c for c in computers if c["delegation"] and not c["disabled"]]
        metadata["computers_total"] = str(len(computers))

        for c in computers:
            entities.append({
                "id":   f"computer:{c['name']}",
                "type": "computer",
                "name": c["name"],
                "props": {
                    "os":         c["os"],
                    "enabled":    str(not c["disabled"]),
                    "lastLogon":  c["lastLogon"],
                    "delegation": str(c["delegation"]),
                },
            })

        if deleg_comp:
            findings.append({
                "id": "unconstrained-delegation-computers", "severity": "critical",
                "title": f"{len(deleg_comp)} equipo(s) con Unconstrained Delegation",
                "description": "Los DCs tienen esto por defecto. Otros equipos con este flag son objetivo prioritario.",
                "evidence": "\n".join(f"  {c['name']}" for c in deleg_comp),
            })

        # Privileged groups
        groups = _priv_groups(conn, base_dn)
        for g in groups:
            if g["members"]:
                findings.append({
                    "id": f"privgroup-{g['name'].lower().replace(' ','-')}", "severity": "info",
                    "title": f"{g['name']}: {len(g['members'])} miembro(s)",
                    "description": "Miembros: " + ", ".join(g["members"][:20]),
                })

        # Trusts
        trusts = _trusts(conn, base_dn)
        metadata["trusts"] = str(len(trusts))
        for t in trusts:
            findings.append({
                "id": f"trust-{t['partner'].replace('.', '-')}", "severity": "info",
                "title": f"Domain trust: {t['partner']}",
                "description": f"Direction: {t['direction']} | Type: {t['type']} | Attrs: {t['attrs']}",
            })

    except Exception as e:
        emit_error(req, f"enumeration error: {e}")
        return
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))

    summary = (
        f"{metadata.get('users_total','?')} usuarios "
        f"({metadata.get('users_enabled','?')} active) · "
        f"{metadata.get('computers_total','?')} equipos · "
        f"{metadata.get('kerberoastable','?')} kerberoastable · "
        f"{metadata.get('asrep_roastable','?')} AS-REP · "
        f"{metadata.get('trusts','?')} trusts · "
        f"{metadata.get('admin_count','?')} adminCount"
    )

    result = {
        "schema_version": 1,
        "module_id":      module_id,
        "summary":        summary,
        "findings":       findings,
        "entities":       entities,
        "metadata":       metadata,
    }

    print(json.dumps({
        "protocol_version": 1,
        "run_id":    run_id,
        "module_id": module_id,
        "ok":        True,
        "result":    result,
    }))


# ── LDAP helpers ──────────────────────────────────────────────────────────────

def _pwdpolicy(conn, base_dn):
    attrs = ["minPwdLength", "lockoutThreshold", "pwdHistoryLength", "maxPwdAge", "minPwdAge"]
    conn.search(base_dn, "(objectClass=domain)", attributes=attrs)
    if not conn.entries:
        return {}
    e = conn.entries[0]
    out = {}
    for a in attrs:
        try:
            v = getattr(e, a).value
            if v is not None:
                out[a] = str(v)
        except Exception:
            pass
    return out


def _users(conn, base_dn):
    attrs = ["sAMAccountName", "userAccountControl", "servicePrincipalName",
             "description", "lastLogon", "pwdLastSet", "adminCount"]
    conn.search(base_dn, "(&(objectCategory=person)(objectClass=user))",
                attributes=attrs, size_limit=5000)
    out = []
    for e in conn.entries:
        try:
            sam = str(getattr(e, "sAMAccountName").value or "")
            if not sam:
                continue
            uac = int(getattr(e, "userAccountControl").value or 0)

            spns = [str(s) for s in (getattr(e, "servicePrincipalName").values or [])
                    if s and not str(s).startswith(MACHINE_SPN_PREFIXES)]

            def _str(attr):
                try:
                    return str(getattr(e, attr).value or "")
                except Exception:
                    return ""

            def _ts(attr):
                try:
                    v = getattr(e, attr).value
                    return ldap_ts(v) if v else ""
                except Exception:
                    return ""

            admin_count = 0
            try:
                ac = getattr(e, "adminCount").value
                admin_count = int(ac) if ac else 0
            except Exception:
                pass

            out.append({
                "sam":         sam,
                "disabled":    bool(uac & UAC_DISABLE),
                "spns":        spns,
                "nopreauth":   bool(uac & UAC_NOPREAUTH),
                "delegation":  bool(uac & UAC_DELEGATION) and not bool(uac & UAC_NODELEG),
                "passnoexpire": bool(uac & UAC_PASSNOEXPIRE),
                "adminCount":  admin_count,
                "description": _str("description"),
                "lastLogon":   _ts("lastLogon"),
                "pwdLastSet":  _ts("pwdLastSet"),
            })
        except Exception:
            continue
    return out


def _computers(conn, base_dn):
    attrs = ["sAMAccountName", "userAccountControl", "operatingSystem", "lastLogon"]
    conn.search(base_dn, "(objectClass=computer)", attributes=attrs, size_limit=1000)
    out = []
    for e in conn.entries:
        try:
            sam = str(getattr(e, "sAMAccountName").value or "")
            name = sam.rstrip("$")
            uac = int(getattr(e, "userAccountControl").value or 0)
            os_str = ""
            try:
                os_str = str(getattr(e, "operatingSystem").value or "")
            except Exception:
                pass
            ll = ""
            try:
                v = getattr(e, "lastLogon").value
                ll = ldap_ts(v) if v else ""
            except Exception:
                pass
            out.append({
                "name":       name,
                "disabled":   bool(uac & UAC_DISABLE),
                "delegation": bool(uac & UAC_DELEGATION) and not bool(uac & UAC_NODELEG),
                "os":         os_str,
                "lastLogon":  ll,
            })
        except Exception:
            continue
    return out


def _priv_groups(conn, base_dn):
    conn.search(base_dn, "(objectClass=group)",
                attributes=["sAMAccountName", "member"], size_limit=1000)
    out = []
    for e in conn.entries:
        try:
            name = str(getattr(e, "sAMAccountName").value or "")
            if name.lower() not in PRIVILEGED_GROUPS:
                continue
            members = []
            for m in (getattr(e, "member").values or []):
                cn = str(m).split(",")[0].replace("CN=", "").replace("cn=", "")
                members.append(cn)
            out.append({"name": name, "members": members})
        except Exception:
            continue
    return out


def _trusts(conn, base_dn):
    direction_map = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
    type_map = {1: "Windows NT", 2: "Active Directory", 3: "MIT Kerberos", 4: "DCE"}
    try:
        conn.search(base_dn, "(objectClass=trustedDomain)",
                    attributes=["trustPartner", "trustType", "trustDirection", "trustAttributes"])
    except Exception:
        return []
    out = []
    for e in conn.entries:
        try:
            partner   = str(getattr(e, "trustPartner").value or "")
            direction = int(getattr(e, "trustDirection").value or 0)
            ttype     = int(getattr(e, "trustType").value or 0)
            tattrs    = int(getattr(e, "trustAttributes").value or 0)
            out.append({
                "partner":   partner,
                "direction": direction_map.get(direction, str(direction)),
                "type":      type_map.get(ttype, str(ttype)),
                "attrs":     hex(tattrs),
            })
        except Exception:
            continue
    return out


def emit_error(req, msg):
    print(json.dumps({
        "protocol_version": 1,
        "run_id":    req.get("run_id", ""),
        "module_id": req.get("module_id", "ad-scan"),
        "ok":        False,
        "error":     msg,
    }))


if __name__ == "__main__":
    main()
