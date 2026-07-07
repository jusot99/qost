import argparse
import asyncio
import json
import time
from pathlib import Path

from qost._shared.output import console
from qost.scan.scanner import (
    DEFAULT_PORTS,
    parse_ports,
    resolve_host,
    scan_ports,
    is_ip,
)


def run(args: argparse.Namespace):
    from qost._shared.utils import iter_targets
    targets_list = iter_targets(args.target, args.file)
    if not targets_list:
        console.print("[red]No targets specified[/]")
        return
    for t in targets_list:
        args.target = t
        asyncio.run(_run(args))


async def _run(args: argparse.Namespace):
    target = args.target
    port_spec = args.ports
    silent = args.silent
    json_out = args.json_out
    output_path = args.output
    timeout = args.timeout
    concurrency = args.concurrency

    start = time.time()

    ports = parse_ports(port_spec) if port_spec else DEFAULT_PORTS

    ip = resolve_host(target)
    if not ip:
        console.print(f"[red]Could not resolve:[/] {target}")
        return

    target_type = "IP Address" if is_ip(target) else "Domain"
    display_target = f"{target} ({ip})" if target_type == "Domain" else target

    if not silent and not json_out:
        from rich.console import Group
        from rich.panel import Panel
        from rich import box
        info = (
            f"[bold cyan]Target:[/] [yellow]{display_target}\n"
            f"[bold cyan]Ports:[/] [green]{len(ports)} ports ({ports[0]}-{ports[-1]})\n"
        )
        console.print(Panel(
            Group(info),
            title="qost scan",
            border_style="cyan",
            box=box.ROUNDED,
            width=80,
        ))

    if not silent and not json_out:
        console.print("[bold]Scanning...[/]")

    results = await scan_ports(target, ports, timeout, concurrency)
    open_ports = [r for r in results if r["state"] == "open"]

    elapsed = round(time.time() - start, 1)

    if json_out or (output_path and output_path.endswith(".json")):
        output = {
            "target": target,
            "ip": ip,
            "type": target_type,
            "ports_scanned": len(ports),
            "open_ports": [
                {k: r[k] for k in ("port", "state", "service", "banner", "tls_cert", "http") if r.get(k)}
                for r in open_ports
            ],
            "duration_seconds": elapsed,
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
        _write_scan_markdown(target, ip, target_type, display_target, ports, open_ports, elapsed, output_path)
        if not silent:
            console.print(f"\n[green]Report written to {output_path}[/]")

    if json_out:
        return

    if not silent:
        if not open_ports:
            console.print("[yellow]No open ports found.[/]")
        else:
            from rich.table import Table
            from rich import box
            t = Table(box=box.SIMPLE, title_justify="left")
            t.add_column("Port", style="cyan", no_wrap=True)
            t.add_column("State", style="green", no_wrap=True)
            t.add_column("Service", style="yellow")
            t.add_column("Banner", style="dim")
            t.add_column("Extra", style="dim")
            for r in open_ports:
                banner = r.get("banner", "")
                if len(banner) > 40:
                    banner = banner[:40] + "..."
                extra = r.get("http", "") or r.get("tls_cert", "") or ""
                if len(extra) > 40:
                    extra = extra[:40] + "..."
                t.add_row(
                    str(r["port"]),
                    r["state"],
                    r.get("service", ""),
                    banner,
                    extra,
                )
            console.print(t)

        from rich.panel import Panel
        from rich import box
        stats = (
            f"[bold cyan]Duration:[/] {elapsed}s\n"
            f"[bold cyan]Ports scanned:[/] {len(ports)}\n"
            f"[bold cyan]Open ports:[/] [green]{len(open_ports)}[/]"
        )
        console.print(Panel(stats, border_style="green", box=box.ROUNDED, width=80))
        console.print("[bold green]Scan complete.[/]")


def _write_scan_markdown(target: str, ip: str, target_type: str, display_target: str, ports: list, open_ports: list, elapsed: float, output_path: str):
    lines = [
        f"# Port Scan Report — {display_target}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Target | {display_target} |",
        f"| IP | {ip} |",
        f"| Type | {target_type} |",
        f"| Ports Scanned | {len(ports)} ({ports[0]}-{ports[-1]}) |",
        f"| Duration | {elapsed}s |",
        "",
    ]
    if open_ports:
        lines.append("## Open Ports")
        lines.append("")
        lines.append("| Port | Service | Banner | Probe |")
        lines.append("|---|---|---|---|")
        for r in open_ports:
            banner = r.get("banner", "")
            if len(banner) > 60:
                banner = banner[:60] + "..."
            extra = r.get("http", "") or r.get("tls_cert", "") or ""
            if len(extra) > 60:
                extra = extra[:60] + "..."
            lines.append(f"| {r['port']} | {r.get('service', '')} | {banner} | {extra} |")
        lines.append("")
    else:
        lines.append("## Results")
        lines.append("")
        lines.append("No open ports found.")
        lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Ports scanned: {len(ports)}")
    lines.append(f"- Open ports: {len(open_ports)}")
    lines.append(f"- Duration: {elapsed}s")
    lines.append("")
    Path(output_path).write_text("\n".join(lines) + "\n")


def register(subparsers):
    p = subparsers.add_parser("scan", help="Port scanning and service detection")
    p.add_argument("target", nargs="?", help="Domain or IP address (optional if --file is used)")
    p.add_argument("--file", "-f", help="File containing targets (one per line, supports CIDR)")
    p.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g. '22,80,443' or '1-1000'). Default: top 50 ports",
    )
    p.add_argument("--timeout", type=float, default=3.0, help="Connect timeout in seconds (default: 3.0)")
    p.add_argument("--concurrency", type=int, default=50, help="Max concurrent connections (default: 50)")
    p.add_argument("--json", "-j", action="store_true", dest="json_out", help="JSON output")
    p.add_argument("--output", "-o", help="Write report to file (.md or .json)")
    p.add_argument("--silent", "-s", action="store_true", help="Suppress terminal output")
    p.set_defaults(func=run)
