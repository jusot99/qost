import argparse
import json
import time
from pathlib import Path

from qost._shared.output import console
from qost.ad.enum import enum_domain, Finding
from qost.ad.smb import check_null_session


def run_enum(args: argparse.Namespace):
    start = time.time()
    target = args.target
    domain = args.domain
    username = args.username or ""
    password = args.password or ""
    json_out = args.json_out
    silent = args.silent
    output_path = args.output

    result = enum_domain(target, domain, username, password)
    result.duration_seconds = round(time.time() - start, 1)

    # SMB null session check
    smb_result = check_null_session(target)
    result.null_session = smb_result
    if smb_result.get("vulnerable"):
        result.findings.append(Finding(
            type="Null Session",
            severity="HIGH",
            detail="Anonymous SMB null session allowed on DC",
            fix="Disable null sessions via GPO: Network access: Do not allow anonymous enumeration of SAM accounts",
        ))

    # Findings severity summary
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in result.findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    # Terminal output
    if not silent and not json_out:
        if result.anonymous_restricted:
            console.print("[yellow]⚠ Anonymous LDAP restricted — DC requires authenticated bind for directory queries. Use -u/-p for full results.[/]")
        from rich.console import Group
        from rich.panel import Panel as RPanel
        from rich.table import Table as RichTable
        from rich import box
        from rich.markdown import Markdown
        from rich.rule import Rule

        auth_mode = "Authenticated" if result.authenticated else "Anonymous"
        summary = RichTable.grid(padding=(0, 2))
        summary.add_column()
        summary.add_row(f"[bold cyan]DC:[/] [yellow]{result.dc_hostname or target} ({target})")
        summary.add_row(f"[bold cyan]Domain:[/] [green]{domain}")
        summary.add_row(f"[bold cyan]Mode:[/] [green]{auth_mode}")
        summary.add_row(f"[bold cyan]Duration:[/] [white]{result.duration_seconds}s[/]")
        console.print(RPanel(
            Group(Markdown("### AD Enumeration"), Rule(style="dim"), summary),
            title="[bold cyan]qost ad enum[/]",
            border_style="cyan",
            box=box.ROUNDED,
            width=80,
        ))

        # Findings table
        if result.findings:
            console.print("\n## Findings", style="bold red")
            ft = RichTable(box=box.SIMPLE)
            ft.add_column("Severity")
            ft.add_column("Finding")
            ft.add_column("Details")
            ft.add_column("Fix")
            colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
            for f in result.findings:
                color = colors.get(f.severity, "white")
                ft.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f"[{color}]{f.type}[/{color}]",
                    f"[{color}]{f.detail}[/{color}]",
                    f"[green]{f.fix}[/green]",
                )
            console.print(ft)
        else:
            console.print("\n[green]No security findings detected[/]")

        # Users
        console.print(f"\n## Users [dim]({len(result.users)} total)[/]", style="bold white")
        if result.admins:
            console.print(f"  [red]Admin Count: {len(result.admins)}[/]")
            for a in result.admins[:10]:
                console.print(f"    [dim]•[/] {a['name']}")
            if len(result.admins) > 10:
                console.print(f"    [dim]... and {len(result.admins) - 10} more[/]")

        # SPNs
        if result.spns:
            console.print(f"\n## SPNs [dim]({len(result.spns)})[/]", style="bold yellow")
            for s in result.spns[:15]:
                console.print(f"  [dim]•[/] {s['name']} → {s['spn']}")
            if len(result.spns) > 15:
                console.print(f"  [dim]... and {len(result.spns) - 15} more[/]")

        # Groups
        if result.groups:
            console.print(f"\n## Groups [dim]({len(result.groups)})[/]", style="bold white")
            for g in result.groups[:20]:
                member_info = f" ({g['member_count']} members)" if g["member_count"] else ""
                desc = f" — {g['description']}" if g["description"] else ""
                console.print(f"  [dim]•[/] {g['name']}{desc}{member_info}")
            if len(result.groups) > 20:
                console.print(f"  [dim]... and {len(result.groups) - 20} more[/]")

        # AS-REP Roastable
        asrep_count = len(result.asrep_users)
        if asrep_count > 0:
            console.print(f"\n## AS-REP Roastable [dim]({asrep_count})[/]", style="bold red")
            for u in result.asrep_users:
                status = "[green]enabled[/]" if u["enabled"] else "[red]disabled[/]"
                console.print(f"  [dim]•[/] {u['name']} ({status})")

        # Unconstrained delegation
        if result.unconstrained:
            console.print(f"\n## Unconstrained Delegation [dim]({len(result.unconstrained)})[/]", style="bold yellow")
            for u in result.unconstrained:
                console.print(f"  [dim]•[/] {u['name']} ({u['dns_hostname']})")

        # Constrained delegation
        if result.constrained:
            console.print(f"\n## Constrained Delegation [dim]({len(result.constrained)})[/]", style="bold yellow")
            for c in result.constrained:
                services = ", ".join(c['allowed_to_delegate'][:3])
                extra = "..." if len(c['allowed_to_delegate']) > 3 else ""
                console.print(f"  [dim]•[/] {c['name']} → {services}{extra}")

        # RBCD
        if result.rbcd:
            console.print(f"\n## RBCD [dim]({len(result.rbcd)})[/]", style="bold red")
            for r in result.rbcd:
                console.print(f"  [dim]•[/] {r['name']} ({r['dns_hostname']})")

        # Computers
        if result.computers:
            console.print(f"\n## Computers [dim]({len(result.computers)})[/]", style="bold white")
            for c in result.computers[:10]:
                os_str = f" {c['os']}" if c["os"] else ""
                console.print(f"  [dim]•[/] {c['name']}{os_str}")
            if len(result.computers) > 10:
                console.print(f"  [dim]... and {len(result.computers) - 10} more[/]")

        # Trusts
        if result.trusts:
            console.print(f"\n## Domain Trusts [dim]({len(result.trusts)})[/]", style="bold white")
            for t in result.trusts:
                console.print(f"  [dim]•[/] {t['name']} → {t['partner']} ({t['direction']})")

        # AD CS
        if result.adcs_servers:
            console.print(f"\n## AD CS Servers [dim]({len(result.adcs_servers)})[/]", style="bold red")
            for s in result.adcs_servers:
                console.print(f"  [dim]•[/] {s['name']} ({s['dns_hostname']})")

        if result.adcs_templates:
            console.print(f"\n## Certificate Templates [dim]({len(result.adcs_templates)})[/]", style="bold yellow")
            for t in result.adcs_templates:
                esc1 = " [red]ESC1[/]" if t["enrollee_supplies_subject"] else ""
                console.print(f"  [dim]•[/] {t['name']}{esc1}")

        # LAPS
        if result.laps_computers:
            console.print(f"\n## LAPS Password Readable [dim]({len(result.laps_computers)})[/]", style="bold red")
            for c in result.laps_computers[:10]:
                console.print(f"  [dim]•[/] {c['name']}")
            if len(result.laps_computers) > 10:
                console.print(f"  [dim]... and {len(result.laps_computers) - 10} more[/]")

        # gMSA
        if result.gmsa_accounts:
            console.print(f"\n## gMSA Accounts [dim]({len(result.gmsa_accounts)})[/]", style="bold white")
            for g in result.gmsa_accounts:
                console.print(f"  [dim]•[/] {g['name']}")

        # SMB signing & LDAP channel binding
        console.print("\n## Security Configurations", style="bold white")
        signing_color = "red" if result.smb_signing == "Not Required" else "green"
        console.print(f"  SMB Signing: [{signing_color}]{result.smb_signing}[/]")
        binding_color = "red" if result.ldap_channel_binding == "Unknown" else "green"
        console.print(f"  LDAP Channel Binding: [{binding_color}]{result.ldap_channel_binding}[/]")

        # SMB null session
        console.print("\n## SMB Null Session", style="bold white")
        if smb_result.get("vulnerable"):
            console.print(f"  [red]Vulnerable:[/] {smb_result['detail']}")
        else:
            console.print(f"  [green]Secure:[/] {smb_result['detail']}")

        # Summary
        console.print("\n## Summary", style="bold white")
        stats = RichTable.grid(padding=(0, 2))
        stats.add_column()
        stats.add_row(f"Duration:   [white]{result.duration_seconds}s[/]")
        stats.add_row(f"Users:      [white]{len(result.users)}[/]")
        stats.add_row(f"Admins:     [white]{len(result.admins)}[/]")
        stats.add_row(f"Computers:  [white]{len(result.computers)}[/]")
        stats.add_row(f"Groups:     [white]{len(result.groups)}[/]")
        stats.add_row(f"SPNs:       [white]{len(result.spns)}[/]")
        stats.add_row(f"AS-REP:     [red]{len(result.asrep_users)}[/]")
        stats.add_row(f"Delegation: [yellow]U:{len(result.unconstrained)} C:{len(result.constrained)} R:{len(result.rbcd)}[/]")
        stats.add_row(f"AD CS:      [red]{'Yes' if result.adcs_servers else 'No'}[/]")
        stats.add_row(f"LAPS/gMSA:  [yellow]{len(result.laps_computers)}/{len(result.gmsa_accounts)}[/]")
        stats.add_row(f"Trusts:     [white]{len(result.trusts)}[/]")
        stats.add_row(f"Findings:   [red]{len(result.findings)}[/] ({severity_counts['HIGH']}H/{severity_counts['MEDIUM']}M/{severity_counts['LOW']}L)")
        console.print(RPanel(stats, border_style="green", box=box.ROUNDED, width=80))
        console.print("\n[bold green]AD Enumeration complete.[/]")

    # JSON output
    if json_out or (output_path and output_path.endswith(".json")):
        output = {
            "target": target,
            "domain": result.domain,
            "dc": result.dc_hostname,
            "authenticated": result.authenticated,
            "anonymous_restricted": result.anonymous_restricted,
            "summary": {
                "users": len(result.users),
                "admins": len(result.admins),
                "computers": len(result.computers),
                "groups": len(result.groups),
                "spns": len(result.spns),
                "asrep_roastable": len(result.asrep_users),
                "unconstrained_delegation": len(result.unconstrained),
                "constrained_delegation": len(result.constrained),
                "rbcd": len(result.rbcd),
                "adcs_servers": len(result.adcs_servers),
                "laps_readable": len(result.laps_computers),
                "gmsa_accounts": len(result.gmsa_accounts),
                "trusts": len(result.trusts),
                "findings": len(result.findings),
            },
            "security": {
                "smb_signing": result.smb_signing,
                "ldap_channel_binding": result.ldap_channel_binding,
            },
            "checks": {
                "ldap_root_dse": {"status": "success", "data": result.root_dse},
                "users": {"status": "success", "count": len(result.users), "total": len(result.users)},
                "admins": {"status": "success", "data": result.admins},
                "computers": {"status": "success", "data": result.computers},
                "groups": {"status": "success", "data": result.groups},
                "spns": {"status": "success", "count": len(result.spns), "data": result.spns},
                "asrep_roastable": {"status": "success", "count": len(result.asrep_users), "data": result.asrep_users},
                "delegation_unconstrained": {"status": "warning" if result.unconstrained else "success", "count": len(result.unconstrained), "data": result.unconstrained},
                "delegation_constrained": {"status": "warning" if result.constrained else "success", "count": len(result.constrained), "data": result.constrained},
                "delegation_rbcd": {"status": "warning" if result.rbcd else "success", "count": len(result.rbcd), "data": result.rbcd},
                "adcs_servers": {"status": "warning" if result.adcs_servers else "success", "count": len(result.adcs_servers), "data": result.adcs_servers},
                "adcs_templates": {"status": "warning" if result.adcs_templates else "success", "count": len(result.adcs_templates), "data": result.adcs_templates},
                "laps_readable": {"status": "warning" if result.laps_computers else "success", "count": len(result.laps_computers), "data": result.laps_computers},
                "gmsa_accounts": {"status": "info" if result.gmsa_accounts else "success", "count": len(result.gmsa_accounts), "data": result.gmsa_accounts},
                "smb_signing": {"status": "warning" if result.smb_signing == "Not Required" else "success", "value": result.smb_signing},
                "ldap_channel_binding": {"status": "warning" if result.ldap_channel_binding == "Unknown" else "success", "value": result.ldap_channel_binding},
                "domain_trusts": {"status": "success", "count": len(result.trusts), "data": result.trusts},
                "null_session": {"status": "vulnerable" if smb_result.get("vulnerable") else smb_result.get("status", "error"), "detail": smb_result.get("detail", "")},
            },
            "findings": [
                {"type": f.type, "severity": f.severity, "detail": f.detail, "fix": f.fix}
                for f in result.findings
            ],
            "duration_seconds": result.duration_seconds,
        }
        json_str = json.dumps(output, indent=2)

        if json_out:
            if output_path and output_path.endswith(".json"):
                Path(output_path).write_text(json_str)
            else:
                print(json_str)
        elif output_path and output_path.endswith(".json"):
            Path(output_path).write_text(json_str)
            if not silent:
                console.print(f"\n[green]JSON report written to {output_path}[/]")

    # Markdown report
    if output_path and not output_path.endswith(".json"):
        _write_markdown(result, smb_result, output_path, severity_counts)
        if not silent:
            console.print(f"\n[green]Report written to {output_path}[/]")


def _write_markdown(result, smb_result, path: str, severity_counts: dict):
    auth_mode = "Authenticated" if result.authenticated else "Anonymous"
    lines = [
        f"# AD Enumeration Report — {result.domain}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| DC | {result.dc_hostname or result.target} ({result.target}) |",
        f"| Domain | {result.domain} |",
        f"| Mode | {auth_mode} |",
        f"| Duration | {result.duration_seconds}s |",
        "",
        *(["> **Note:** Anonymous LDAP queries are restricted. Use `-u USER -p PASS` for full enumeration."] if result.anonymous_restricted else []),
    ]

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | Finding | Details | Fix |")
        lines.append("|---|---|---|---|")
        for f in result.findings:
            lines.append(f"| {f.severity} | {f.type} | {f.detail} | {f.fix} |")
        lines.append("")

    lines.append(f"## Users ({len(result.users)} total)")
    lines.append("")
    if result.admins:
        lines.append(f"- **Domain Admins ({len(result.admins)}):** " + ", ".join(a["name"] for a in result.admins))
    lines.append(f"- SPN-enabled: {len(result.spns)}")
    lines.append(f"- AS-REP Roastable: {len(result.asrep_users)}")
    lines.append("")

    if result.asrep_users:
        lines.append("## AS-REP Roastable")
        lines.append("")
        lines.append("| User | Enabled |")
        lines.append("|---|---|")
        for u in result.asrep_users:
            lines.append(f"| {u['name']} | {u['enabled']} |")
        lines.append("")

    if result.spns:
        lines.append("## Service Accounts (SPNs)")
        lines.append("")
        lines.append("| Account | SPN | Enabled |")
        lines.append("|---|---|---|")
        for s in result.spns:
            lines.append(f"| {s['name']} | {s['spn']} | {s['enabled']} |")
        lines.append("")

    if result.unconstrained:
        lines.append("## Unconstrained Delegation")
        lines.append("")
        for u in result.unconstrained:
            lines.append(f"- {u['name']} ({u['dns_hostname']})")
        lines.append("")

    if result.constrained:
        lines.append("## Constrained Delegation")
        lines.append("")
        for c in result.constrained:
            services = ", ".join(c['allowed_to_delegate'][:3])
            lines.append(f"- {c['name']} → {services}")
        lines.append("")

    if result.rbcd:
        lines.append("## Resource-Based Constrained Delegation (RBCD)")
        lines.append("")
        for r in result.rbcd:
            lines.append(f"- {r['name']} ({r['dns_hostname']})")
        lines.append("")

    if result.adcs_servers:
        lines.append("## AD CS Servers")
        lines.append("")
        for s in result.adcs_servers:
            lines.append(f"- {s['name']} ({s['dns_hostname']})")
        lines.append("")

    if result.adcs_templates:
        lines.append("## Certificate Templates")
        lines.append("")
        for t in result.adcs_templates:
            esc1 = " [ESC1]" if t["enrollee_supplies_subject"] else ""
            lines.append(f"- {t['name']}{esc1}")
        lines.append("")

    if result.laps_computers:
        lines.append("## LAPS Password Readable")
        lines.append("")
        for c in result.laps_computers:
            lines.append(f"- {c['name']}")
        lines.append("")

    if result.gmsa_accounts:
        lines.append("## gMSA Accounts")
        lines.append("")
        for g in result.gmsa_accounts:
            lines.append(f"- {g['name']}")
        lines.append("")

    if result.smb_signing:
        lines.append(f"- SMB Signing: {result.smb_signing}")
    if result.ldap_channel_binding:
        lines.append(f"- LDAP Channel Binding: {result.ldap_channel_binding}")

    if result.computers:
        lines.append(f"## Computers ({len(result.computers)})")
        lines.append("")
        for c in result.computers:
            os_str = f" — {c['os']}" if c["os"] else ""
            lines.append(f"- {c['name']}{os_str}")
        lines.append("")

    if result.trusts:
        lines.append("## Domain Trusts")
        lines.append("")
        lines.append("| Name | Partner | Direction |")
        lines.append("|---|---|---|")
        for t in result.trusts:
            lines.append(f"| {t['name']} | {t['partner']} | {t['direction']} |")
        lines.append("")

    lines.append("## SMB Null Session")
    lines.append("")
    if smb_result.get("vulnerable"):
        lines.append(f"- **Vulnerable:** {smb_result['detail']}")
    else:
        lines.append(f"- **Secure:** {smb_result['detail']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Duration: {result.duration_seconds}s")
    lines.append(f"- Users: {len(result.users)}")
    lines.append(f"- Admins: {len(result.admins)}")
    lines.append(f"- Computers: {len(result.computers)}")
    lines.append(f"- Groups: {len(result.groups)}")
    lines.append(f"- SPNs: {len(result.spns)}")
    lines.append(f"- AS-REP Roastable: {len(result.asrep_users)}")
    lines.append(f"- Unconstrained Delegation: {len(result.unconstrained)}")
    lines.append(f"- Constrained Delegation: {len(result.constrained)}")
    lines.append(f"- RBCD: {len(result.rbcd)}")
    lines.append(f"- AD CS Servers: {len(result.adcs_servers)}")
    lines.append(f"- LAPS Readable: {len(result.laps_computers)}")
    lines.append(f"- gMSA Accounts: {len(result.gmsa_accounts)}")
    lines.append(f"- SMB Signing: {result.smb_signing}")
    lines.append(f"- LDAP Channel Binding: {result.ldap_channel_binding}")
    lines.append(f"- Domain Trusts: {len(result.trusts)}")
    lines.append(f"- Findings: {len(result.findings)} ({severity_counts['HIGH']}H/{severity_counts['MEDIUM']}M/{severity_counts['LOW']}L)")
    lines.append("")

    Path(path).write_text("\n".join(lines) + "\n")


def register(subparsers):
    p = subparsers.add_parser("ad", help="Active Directory enumeration and assessment")
    ad_sub = p.add_subparsers(dest="ad_command", required=True)

    enum_p = ad_sub.add_parser("enum", help="Enumerate an Active Directory domain")
    enum_p.add_argument("target", help="DC IP address or hostname")
    enum_p.add_argument("-d", "--domain", required=True, help="Domain name (e.g. corp.local)")
    enum_p.add_argument("-u", "--username", help="Username for authenticated enumeration")
    enum_p.add_argument("-p", "--password", help="Password for authenticated enumeration")
    enum_p.add_argument("--json", "-j", action="store_true", dest="json_out", help="JSON output")
    enum_p.add_argument("--silent", "-s", action="store_true", help="Suppress terminal output")
    enum_p.add_argument("--output", "-o", help="Write report to file (.md or .json)")
    enum_p.set_defaults(func=run_enum)
