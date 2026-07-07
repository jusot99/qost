import argparse
import asyncio
import json
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx

from qost._shared.output import (
    console,
    panel,
)
from qost._shared.utils import is_ip, iter_targets
from qost.recon import portscan, scanner, security, subdomain, utils

logger = logging.getLogger(__name__)


_DISABLE_VERIFY = True


async def http_probe(host: str) -> dict:
    result: dict[str, Any] = {"url": None, "status": None, "title": None, "server": None}
    async with httpx.AsyncClient(timeout=5, verify=not _DISABLE_VERIFY, follow_redirects=True) as c:
        for scheme in ("https", "http"):
            try:
                r = await c.get(f"{scheme}://{host}")
                result["url"] = str(r.url)
                result["status"] = r.status_code
                result["server"] = r.headers.get("server", "")
                match = re.search(
                    rb"<title[^>]*>(.*?)</title>", r.content, re.IGNORECASE
                )
                if match:
                    result["title"] = (
                        match.group(1).decode(errors="replace").strip()[:80]
                    )
                break
            except Exception:
                continue
    return result


async def enrich_asn(ip: str) -> dict | None:
    async with httpx.AsyncClient(timeout=10, verify=not _DISABLE_VERIFY) as c:
        # Try ipinfo.io first as it's very reliable for both v4 and v6
        try:
            r = await c.get(f"https://ipinfo.io/{ip}/json")
            if r.status_code == 200:
                data = r.json()
                org = data.get("org", "")
                if org:
                    return {"name": org}
        except Exception as exc:
            logger.debug("IP info lookup failed for %s: %s", ip, exc)

        try:
            r = await c.get(f"https://rdap.arin.net/registry/ip/{ip}")
            if r.status_code == 200:
                data = r.json()
                name = ""
                for ent in data.get("entities", []):
                    va = ent.get("vcardArray", [])
                    if len(va) > 1:
                        for vcard in va[1]:
                            if vcard[0] == "fn":
                                name = vcard[3]
                if name:
                    return {"name": name}
        except Exception as exc:
            logger.debug("RDAP lookup failed for %s: %s", ip, exc)
    return None


def run(args: argparse.Namespace):
    targets_list = iter_targets(args.target, args.file)
    if not targets_list:
        console.print("[red]No targets specified[/]")
        return
    for t in targets_list:
        args.target = t
        asyncio.run(_run(args))


async def _run(args: argparse.Namespace):
    target = args.target
    brute = args.brute
    wordlist_path = args.wordlist
    silent = args.silent
    json_out = args.json_out
    output_path = args.output
    global _DISABLE_VERIFY
    _DISABLE_VERIFY = not args.verify

    start = time.time()
    records_map = {
        "A": "a", "AAAA": "aaaa", "MX": "mx", "NS": "ns",
        "TXT": "txt", "CNAME": "cname", "SOA": "soa",
        "SRV": "srv", "CAA": "caa", "SSHFP": "sshfp",
        "TLSA": "tlsa", "NAPTR": "naptr", "DNSKEY": "dnskey",
        "DS": "ds",
    }
    all_records: dict[str, list[str]] = {}
    resolved_ips: set[str] = set()
    ns_list: list[str] = []
    live_hosts: list[tuple[str, str]] = []
    subdomains: list[str] = []
    vulnerabilities: list[security.Vuln] = []

    target_type = "IP Address" if is_ip(target) else "Domain"
    display_target = target

    if is_ip(target):
        ptr = utils.get_ptr(target)
        if ptr:
            display_target = f"{target} ({ptr})"
    else:
        ip = utils.resolve_ip(target)
        if ip:
            resolved_ips.add(ip)

    # ── Header ──
    if not silent and not json_out:
        from rich.console import Group
        from rich.markdown import Markdown
        from rich.rule import Rule
        from rich.table import Table as RichTable
        from rich import box
        summary = RichTable.grid(padding=(0, 2))
        summary.add_column()
        summary.add_row(f"[bold cyan]Target:[/] [yellow]{display_target}")
        summary.add_row(f"[bold cyan]Type:[/] [green]{target_type}")
        scan_mode = "Full Reconnaissance" if brute else "Standard"
        summary.add_row(f"[bold cyan]Mode:[/] [green]{scan_mode}")
        panel(
            "qost recon",
            Group(Markdown("### Ghost DNS Recon"), Rule(style="dim"), summary),
            border="cyan",
            width=80,
        )

    # ── Phase 1: DNS Records ──
    if not silent and not json_out:
        console.print("## Phase 1: DNS Records", style="bold magenta")

    results = await scanner.resolve_all(target, args.resolver or None)

    for rtype, attr in records_map.items():
        answers, err = results.get(rtype, (None, None))
        if is_ip(target) and rtype != "A":
            continue

        if answers:
            rows: list[str] = []
            for rdata in answers:
                val = scanner.format_rdata(rdata, rtype)
                rows.append(val)
                all_records.setdefault(rtype, []).append(val)

                if rtype == "NS":
                    ns_str = str(rdata.target).rstrip(".")
                    if ns_str not in ns_list:
                        ns_list.append(ns_str)

            if not silent and not json_out:
                from rich.table import Table as RichTable
                t = RichTable(title=f"{rtype} Records", box=box.SIMPLE, title_justify="left")
                t.add_column("Value", style="cyan")
                for row in rows:
                    t.add_row(row)
                console.print(t)
        elif not silent and not json_out:
            if err:
                console.print(f"  [dim]{rtype}:[/] [red]{err}")
            else:
                console.print(f"  [dim]{rtype}:[/] [yellow]No records found[/]")

    if not silent and not json_out:
        console.print()

    # ── Phase 2: Security Assessment ──
    if not silent and not json_out:
        console.print("## Phase 2: Security Assessment", style="bold red")

    if is_ip(target):
        if not silent and not json_out:
            console.print("  [yellow]Skipped for IP addresses[/]")
    else:
        txt_records = [str(r) for r in all_records.get("TXT", [])]
        vulnerabilities += await security.check_spf_dmarc(target, txt_records)
        vulnerabilities += security.check_dnssec(
            all_records.get("DNSKEY", []), all_records.get("DS", [])
        )
        vulnerabilities += security.check_takeover(all_records.get("CNAME", []))

        if not silent and not json_out:
            if vulnerabilities:
                from rich.table import Table as RichTable
                vt = RichTable(box=box.SIMPLE)
                vt.add_column("Severity")
                vt.add_column("Issue")
                vt.add_column("Fix")
                colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
                for v in vulnerabilities:
                    c = colors.get(v.severity, "white")
                    vt.add_row(
                        f"[{c}]{v.severity}[/{c}]",
                        f"[{c}]{v.detail}[/{c}]",
                        f"[green]{v.fix}[/green]",
                    )
                console.print(vt)
            else:
                console.print("  [green]No security issues detected[/]")
    if not silent and not json_out:
        console.print()

    # ── Phase 3: Zone Transfer ──
    if not silent and not json_out:
        console.print("## Phase 3: Zone Transfer Testing", style="bold blue")

    if is_ip(target):
        if not silent and not json_out:
            console.print("  [yellow]Skipped for IP addresses[/]")
    elif not ns_list:
        if not silent and not json_out:
            console.print("  [yellow]No NS servers found[/]")
    else:
        vulnerable_ns = []
        for ns in ns_list:
            hosts, err = scanner.zone_transfer(ns, target)
            if hosts:
                vulnerable_ns.append((ns, hosts))
                if not silent and not json_out:
                    console.print(f"  [red bold]VULNERABLE:[/] {ns}")
                    console.print(f"    [green]{len(hosts)} records retrieved[/]")
                    for h in hosts[:5]:
                        console.print(f"    [dim]• {h['name']} → {h['data']}[/]")
            else:
                if not silent and not json_out:
                    console.print(f"  [green]Secure:[/] {ns}")
        if vulnerable_ns and not silent and not json_out:
            console.print(
                f"\n[red bold]CRITICAL:[/] {len(vulnerable_ns)} nameserver(s) allow zone transfers!"
            )
    if not silent and not json_out:
        console.print()

    # ── Phase 4: Subdomain Discovery ──
    if not silent and not json_out:
        console.print("## Phase 4: Subdomain Discovery", style="bold green")

    if is_ip(target):
        if not silent and not json_out:
            console.print("  [yellow]Skipped for IP addresses[/]")
    else:
        if not silent and not json_out:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
                ) as progress:
                    progress.add_task("Gathering subdomains...", total=None)
                    subs = await subdomain.find_subdomains(target, verify=not _DISABLE_VERIFY)
        else:
            subs = await subdomain.find_subdomains(target, verify=not _DISABLE_VERIFY)

        subdomains = subs

        if not silent and not json_out:
            if subdomains:
                from rich.table import Table as RichTable
                from rich import box
                st = RichTable(box=box.SIMPLE)
                st.add_column("#")
                st.add_column("Subdomain", style="cyan")
                for i, s in enumerate(subdomains[:25], 1):
                    st.add_row(str(i), s)
                console.print(st)
                if len(subdomains) > 25:
                    console.print(f"  [dim]... and {len(subdomains) - 25} more[/]")
            else:
                console.print("  [yellow]No subdomains found in certificate logs[/]")

        if brute:
            if not silent and not json_out:
                console.print("\n[bold]Subdomain Bruteforce:[/]")
            brute_subs = subdomain.brute_force(target, wordlist_path)
            new = [s for s in brute_subs if s not in subdomains]
            if new:
                if not silent and not json_out:
                    console.print(f"  [green]Found {len(new)} new subdomains:[/]")
                for s in new:
                    subdomains.append(s)
                    if not silent and not json_out:
                        console.print(f"    [dim]•[/] {s}")
            else:
                if not silent and not json_out:
                    console.print("  [yellow]No additional subdomains found[/]")
    if not silent and not json_out:
        console.print()

    # ── Phase 5: Live Host Detection ──
    if not silent and not json_out:
        console.print("## Phase 5: Live Host Detection", style="bold yellow")

    targets = [target] + (subdomains if subdomains else [])

    def check(host: str) -> list[tuple[str, str]]:
        try:
            ips = utils.resolve_all_ips(host)
            return [(host, ip) for ip in ips]
        except (socket.gaierror, OSError):
            pass
        return []

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check, h): h for h in targets}
        for f in as_completed(futures):
            for r in f.result():
                if r:
                    live_hosts.append(r)
                    resolved_ips.add(r[1])

    if not silent and not json_out:
        console.print(f"  [bold]{len(live_hosts)}[/] hosts resolved\n")

    host_details = []
    # Probe all hosts for JSON, but limit to 10 for terminal to avoid clutter
    hosts_to_probe = live_hosts if json_out else live_hosts[:10]
    
    if not json_out and not silent and len(live_hosts) > 10:
        console.print("  [yellow]Note:[/] Probing only the first 10 hosts for terminal view. Use [bold]--json[/] for full results.\n")

    for host, ip in hosts_to_probe:
        probe = await http_probe(host)
        # Port scan only if limited number of IPs to avoid being blocked/slow
        ports = portscan.scan(ip) if len(resolved_ips) < 20 else []
        
        detail: dict[str, Any] = {
            "host": host,
            "ip": ip,
            "http": probe,
            "ports": [{"port": p, "service": s} for p, s in ports],
            "asn": await enrich_asn(ip)
        }
        host_details.append(detail)

        if not silent and not json_out:
            from rich.tree import Tree
            tree = Tree(f"[cyan]{host}[/] → [green]{ip}[/]")
            if probe["status"]:
                sc = "green" if probe["status"] < 400 else "yellow" if probe["status"] < 500 else "red"
                tree.add(f"HTTP: [bold {sc}]{probe['status']}[/]")
            if probe["title"]:
                tree.add(f"Title: [white]{probe['title']}[/]")
            if probe["server"]:
                tree.add(f"Server: [dim]{probe['server']}[/]")
            if ports:
                p_str = ", ".join(f"{p}({s})" for p, s in ports[:6])
                tree.add(f"Ports: [yellow]{p_str}[/]")
            if detail["asn"] and detail["asn"]["name"]:
                tree.add(f"ASN: [dim]{detail['asn']['name']}[/]")
            console.print(tree)

    if not silent and not json_out:
        console.print()

    # ── Summary ──
    elapsed = time.time() - start
    if not silent and not json_out:
        console.print("## Summary", style="bold white")
        from rich.table import Table as RichTable
        stats = RichTable.grid(padding=(0, 2))
        stats.add_column()
        stats.add_row(f"Scan Duration:   [white]{elapsed:.1f}s[/]")
        stats.add_row(f"Record Types:    [white]{sum(1 for v in all_records.values() if v)}[/]")
        stats.add_row(f"Subdomains:      [white]{len(subdomains)}[/]")
        stats.add_row(f"Live Hosts:      [white]{len(live_hosts)}[/]")
        stats.add_row(f"Vulnerabilities: [white]{len(vulnerabilities)}[/]")
        stats.add_row(f"IPs Resolved:    [white]{len(resolved_ips)}[/]")
        from rich.panel import Panel as RPanel
        from rich import box
        console.print(RPanel(stats, border_style="green", box=box.ROUNDED, width=80))
        console.print("\n[bold green]Reconnaissance complete.[/]")

    if json_out or (output_path and output_path.endswith(".json")):
        output = {
            "target": target,
            "type": target_type,
            "records": all_records,
            "nameservers": ns_list,
            "subdomains": sorted(subdomains),
            "live_hosts": host_details,
            "vulnerabilities": [
                {"type": v.type, "severity": v.severity, "detail": v.detail, "fix": v.fix}
                for v in vulnerabilities
            ],
            "duration_seconds": round(elapsed, 1),
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
        _write_recon_markdown(output_path, target, target_type, display_target, brute, all_records, ns_list, subdomains, host_details, vulnerabilities, elapsed)
        if not silent:
            console.print(f"\n[green]Report written to {output_path}[/]")


def _write_recon_markdown(output_path: str, target: str, target_type: str, display_target: str, brute: bool, all_records: dict, ns_list: list, subdomains: list, host_details: list, vulnerabilities: list, elapsed: float):
    lines = [
        f"# Reconnaissance Report — {display_target}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Target | {display_target} |",
        f"| Type | {target_type} |",
        f"| Mode | {'Full Reconnaissance' if brute else 'Standard'} |",
        f"| Duration | {elapsed:.1f}s |",
        "",
    ]
    if all_records:
        lines.append("## DNS Records")
        lines.append("")
        for rtype, records in sorted(all_records.items()):
            if records:
                lines.append(f"### {rtype} Records")
                lines.append("")
                for r in records:
                    lines.append(f"- {r}")
                lines.append("")
    if subdomains:
        lines.append(f"## Subdomains ({len(subdomains)})")
        lines.append("")
        for s in sorted(subdomains):
            lines.append(f"- {s}")
        lines.append("")
    if host_details:
        lines.append(f"## Live Hosts ({len(host_details)})")
        lines.append("")
        for h in host_details:
            http = h.get("http", {})
            ports = h.get("ports", [])
            asn = h.get("asn")
            line = f"- **{h['host']}** → {h['ip']}"
            if http.get("status"):
                line += f" | HTTP {http['status']}"
            if http.get("title"):
                line += f" | {http['title']}"
            if ports:
                line += " | Ports: " + ", ".join(f"{p['port']}({p['service']})" for p in ports[:5])
            if asn and asn.get("name"):
                line += f" | ASN: {asn['name']}"
            lines.append(line)
        lines.append("")
    if vulnerabilities:
        lines.append("## Vulnerabilities")
        lines.append("")
        lines.append("| Severity | Issue | Fix |")
        lines.append("|---|---|---|")
        for v in vulnerabilities:
            lines.append(f"| {v.severity} | {v.detail} | {v.fix} |")
        lines.append("")
    if ns_list:
        lines.append("## Nameservers")
        lines.append("")
        for ns in ns_list:
            lines.append(f"- {ns}")
        lines.append("")
    lines.append("## Summary")
    lines.append("")
    for rtype, records in sorted(all_records.items()):
        if records:
            lines.append(f"- {rtype}: {len(records)} records")
    lines.append(f"- Subdomains: {len(subdomains)}")
    lines.append(f"- Live Hosts: {len(host_details)}")
    lines.append(f"- Vulnerabilities: {len(vulnerabilities)}")
    lines.append(f"- Duration: {elapsed:.1f}s")
    lines.append("")
    Path(output_path).write_text("\n".join(lines) + "\n")


def register(subparsers):
    p = subparsers.add_parser("recon", help="DNS reconnaissance and subdomain enumeration")
    p.add_argument("target", nargs="?", help="Domain or IP address (optional if --file is used)")
    p.add_argument("--file", "-f", help="File containing targets (one per line, supports CIDR)")
    p.add_argument("--brute", "-b", action="store_true", help="Enable subdomain bruteforce")
    p.add_argument("--wordlist", "-w", help="Path to wordlist file")
    p.add_argument("--resolver", "-r", action="append", help="Custom DNS resolver")
    p.add_argument("--json", "-j", action="store_true", dest="json_out", help="JSON output")
    p.add_argument("--output", "-o", help="Write report to file (.md or .json)")
    p.add_argument("--silent", "-s", action="store_true", help="Suppress terminal output")
    p.add_argument("--verify", action="store_true", help="Enable SSL certificate verification (default: disabled)")
    p.set_defaults(func=run)
