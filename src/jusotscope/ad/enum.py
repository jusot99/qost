from dataclasses import dataclass, field
from typing import Any

from ldap3 import ALL, ANONYMOUS, NTLM, Connection, Server


@dataclass
class Finding:
    type: str
    severity: str
    detail: str
    fix: str


@dataclass
class EnumResult:
    target: str = ""
    domain: str = ""
    dc_hostname: str = ""
    authenticated: bool = False
    anonymous_restricted: bool = False
    ldap_error: str = ""
    root_dse: dict = field(default_factory=dict)
    users: list[dict] = field(default_factory=list)
    admins: list[dict] = field(default_factory=list)
    computers: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    spns: list[dict] = field(default_factory=list)
    asrep_users: list[dict] = field(default_factory=list)
    unconstrained: list[dict] = field(default_factory=list)
    trusts: list[dict] = field(default_factory=list)
    null_session: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0


def _decode(val: Any) -> str:
    if isinstance(val, bytes):
        return val.decode(errors="replace")
    if isinstance(val, list):
        return ", ".join(str(_decode(v)) for v in val)
    return str(val)


def _safe(entry: dict, attr: str) -> str:
    raw = entry.get(attr)
    if isinstance(raw, list):
        return _decode(raw[0]) if raw else ""
    if raw:
        return _decode(raw)
    return ""


def _safe_list(entry: dict, attr: str) -> list[str]:
    raw = entry.get(attr)
    if isinstance(raw, list):
        return [_decode(v) for v in raw]
    if raw:
        return [_decode(raw)]
    return []


def enum_domain(target: str, domain: str, username: str = "", password: str = "") -> EnumResult:
    result = EnumResult(target=target, domain=domain)

    auth: str = ANONYMOUS
    user = None
    if username:
        auth = NTLM
        user = f"{domain}\\{username}"

    server = Server(target, get_info=ALL)
    conn = Connection(server, authentication=auth, user=user, password=password, auto_bind=True)  # type: ignore[arg-type]
    result.authenticated = bool(username)

    # Root DSE
    info = server.info
    if info:
        dse = {}
        for k in ("defaultNamingContext", "rootDomainNamingContext", "dnsHostName", "domainControllerFunctionality", "forestFunctionality", "domainFunctionality", "namingContexts", "supportedCapabilities", "supportedLDAPVersion"):
            raw = getattr(info, k, None) or info.raw.get(k)
            if raw:
                dse[k] = _decode(raw)
        result.root_dse = dse
        nc = (info.raw.get("defaultNamingContext") or [b""])[0]
        if isinstance(nc, bytes):
            nc = nc.decode()
    else:
        nc = ""

    base = result.root_dse.get("defaultNamingContext", nc) or nc
    dns_host = result.root_dse.get("dnsHostName", "")
    result.dc_hostname = dns_host

    if not base:
        conn.unbind()
        return result

    def _search(filter_str: str, attrs: list[str]) -> bool:
        ok = conn.search(base, filter_str, attributes=attrs)
        if not ok:
            desc = conn.result.get("description", "")
            msg = conn.result.get("message", "")
            if "successful bind" in msg.lower() or desc in ("operationsError", "insufficientAccessRights"):
                result.anonymous_restricted = True
                result.ldap_error = msg
            return False
        return True

    def _paged_search(filter_str: str, attrs: list[str], page_size: int = 500) -> list:
        entries = []
        cookie = True
        while cookie:
            conn.search(base, filter_str, attributes=attrs, paged_size=page_size)
            if conn.result.get("description") in ("operationsError", "insufficientAccessRights"):
                return []
            entries.extend(conn.entries)
            cookie = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie", b"")
            if not cookie:
                break
        return entries

    if not _search("(objectClass=user)", ["sAMAccountName", "displayName", "userPrincipalName", "mail", "adminCount", "userAccountControl", "memberOf", "description", "whenCreated", "pwdLastSet"]):
        conn.unbind()
        if result.anonymous_restricted:
            result.findings.append(Finding(
                type="Anonymous LDAP Restricted",
                severity="INFO",
                detail="DC does not allow anonymous LDAP queries for directory objects. Authenticate with -u/-p for full enumeration.",
                fix="Use domain credentials with -u USER -p PASS",
            ))
        return result
    for e in conn.entries:
        entry = e.entry_attributes_as_dict
        uac = int(_safe(entry, "userAccountControl") or "0")
        enabled = not bool(uac & 2)
        result.users.append({
            "name": _safe(entry, "sAMAccountName"),
            "display": _safe(entry, "displayName"),
            "upn": _safe(entry, "userPrincipalName"),
            "mail": _safe(entry, "mail"),
            "admin_count": bool(_safe(entry, "adminCount")),
            "enabled": enabled,
            "description": _safe(entry, "description"),
            "when_created": _safe(entry, "whenCreated"),
        })
        if result.users[-1]["admin_count"]:
            result.admins.append(result.users[-1])

    # SPNs
    if _search("(&(objectClass=user)(servicePrincipalName=*))", ["sAMAccountName", "servicePrincipalName", "enabled", "userAccountControl"]):
        for e in conn.entries:
            entry = e.entry_attributes_as_dict
            uac = int(_safe(entry, "userAccountControl") or "0")
            enabled = not bool(uac & 2)
            for spn in _safe_list(entry, "servicePrincipalName"):
                if spn not in result.spns:
                    result.spns.append({
                        "name": _safe(entry, "sAMAccountName"),
                        "spn": spn,
                        "enabled": enabled,
                    })

    # AS-REP roastable
    if _search("(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", ["sAMAccountName", "enabled", "userAccountControl"]):
        for e in conn.entries:
            entry = e.entry_attributes_as_dict
            uac = int(_safe(entry, "userAccountControl") or "0")
            enabled = not bool(uac & 2)
            result.asrep_users.append({
                "name": _safe(entry, "sAMAccountName"),
                "enabled": enabled,
            })
    result.findings.append(Finding(
        type="AS-REP Roastable",
        severity="HIGH" if result.asrep_users else "INFO",
        detail=f"{len(result.asrep_users)} user(s) without Kerberos pre-authentication",
        fix="Enable 'Account does not require Kerberos pre-authentication' = disabled for affected users",
    ))

    # Unconstrained delegation
    if _search("(userAccountControl:1.2.840.113556.1.4.803:=524288)", ["sAMAccountName", "dNSHostName", "userAccountControl"]):
        for e in conn.entries:
            entry = e.entry_attributes_as_dict
            result.unconstrained.append({
                "name": _safe(entry, "sAMAccountName"),
                "dns_hostname": _safe(entry, "dNSHostName"),
            })
    if result.unconstrained:
        result.findings.append(Finding(
            type="Unconstrained Delegation",
            severity="MEDIUM",
            detail=f"{len(result.unconstrained)} computer(s)/user(s) with unconstrained delegation",
            fix="Use constrained delegation instead; review which accounts truly need it",
        ))

    # Computers
    if _search("(objectClass=computer)", ["sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "userAccountControl", "description"]):
        for e in conn.entries:
            entry = e.entry_attributes_as_dict
            uac = int(_safe(entry, "userAccountControl") or "0")
            enabled = not bool(uac & 2)
            result.computers.append({
                "name": _safe(entry, "sAMAccountName"),
                "dns_hostname": _safe(entry, "dNSHostName"),
                "os": _safe(entry, "operatingSystem"),
                "os_version": _safe(entry, "operatingSystemVersion"),
                "enabled": enabled,
                "description": _safe(entry, "description"),
            })

    # Groups
    for e in _paged_search("(objectClass=group)", ["sAMAccountName", "description", "member", "distinguishedName"]):
        entry = e.entry_attributes_as_dict
        result.groups.append({
            "name": _safe(entry, "sAMAccountName"),
            "description": _safe(entry, "description"),
            "member_count": len(_safe_list(entry, "member")),
        })

    # Domain Trusts
    for e in _paged_search("(objectClass=trustedDomain)", ["cn", "trustAttributes", "trustDirection", "trustType", "trustPartner"]):
        entry = e.entry_attributes_as_dict
        direction_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        td = int(_safe(entry, "trustDirection") or "3")
        result.trusts.append({
            "name": _safe(entry, "cn"),
            "partner": _safe(entry, "trustPartner"),
            "direction": direction_map.get(td, str(td)),
            "type": _safe(entry, "trustType"),
        })

    conn.unbind()
    return result
