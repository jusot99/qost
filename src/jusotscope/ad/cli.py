import argparse
import json
import time
from pathlib import Path

from jusotscope._shared.output import console
from jusotscope.ad.enum import enum_domain, Finding
from jusotscope.ad.smb import check_null_session


def run_enum(args: argparse.Namespace):
    start = time.time()
    target = args.target
    domain = args.domain
    username = args.username or ""
    password = args.password or ""
    json_out = args.json_out
    silent = args.silent
    output_path = args.output
    if output_path and output_path.endswith(".json"):
        json_out = True

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
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

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
            title="[bold cyan]jusotscope ad enum[/]",
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
                c = colors.get(f.severity, "white")
                ft.add_row(
                    f"[{c}]{f.severity}[/{c}]",
                    f"[{c}]{f.type}[/{c}]",
                    f"[{c}]{f.detail}[/{c}]",
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

        # AS-REP
        if result.asrep_users:
            console.print(f"\n## AS-REP Roastable [dim]({len(result.asrep_users)})[/]", style="bold red")
            for u in result.asrep_users:
                status = "[green]enabled[/]" if u["enabled"] else "[red]disabled[/]"
                console.print(f"  [dim]•[/] {u['name']} ({status})")

        # Unconstrained delegation
        if result.unconstrained:
            console.print(f"\n## Unconstrained Delegation [dim]({len(result.unconstrained)})[/]", style="bold yellow")
            for u in result.unconstrained:
                console.print(f"  [dim]•[/] {u['name']} ({u['dns_hostname']})")

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

        # SMB null session
        console.print(f"\n## SMB Null Session", style="bold white")
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
        stats.add_row(f"Delegation: [yellow]{len(result.unconstrained)}[/]")
        stats.add_row(f"Trusts:     [white]{len(result.trusts)}[/]")
        stats.add_row(f"Findings:   [red]{len(result.findings)}[/] ({severity_counts.get('HIGH', 0)}H/{severity_counts.get('MEDIUM', 0)}M/{severity_counts.get('LOW', 0)}L)")
        console.print(RPanel(stats, border_style="green", box=box.ROUNDED, width=80))
        console.print("\n[bold green]AD Enumeration complete.[/]")

    # JSON output
    if json_out:
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
                "trusts": len(result.trusts),
                "findings": len(result.findings),
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
        if output_path and output_path.endswith(".json"):
            Path(output_path).write_text(json_str)
        else:
            print(json_str)

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

    lines.append(f"## Summary")
    lines.append("")
    lines.append(f"- Duration: {result.duration_seconds}s")
    lines.append(f"- Users: {len(result.users)}")
    lines.append(f"- Admins: {len(result.admins)}")
    lines.append(f"- Computers: {len(result.computers)}")
    lines.append(f"- Groups: {len(result.groups)}")
    lines.append(f"- SPNs: {len(result.spns)}")
    lines.append(f"- AS-REP Roastable: {len(result.asrep_users)}")
    lines.append(f"- Unconstrained Delegation: {len(result.unconstrained)}")
    lines.append(f"- Domain Trusts: {len(result.trusts)}")
    lines.append(f"- Findings: {len(result.findings)} ({severity_counts.get('HIGH', 0)}H/{severity_counts.get('MEDIUM', 0)}M/{severity_counts.get('LOW', 0)}L)")
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
