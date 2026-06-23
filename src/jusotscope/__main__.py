import argparse
import importlib.metadata
import signal
import sys

from rich.panel import Panel

from jusotscope._shared.output import console


if getattr(sys, "frozen", False):
    from jusotscope._version import __version__
else:
    try:
        __version__ = importlib.metadata.version("jusotscope")
    except importlib.metadata.PackageNotFoundError:
        from jusotscope._version import __version__


HEADINGS = frozenset({
    "positional arguments:", "optional arguments:", "options:", "Examples:",
})


class _ColoredParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        text = self.format_help()
        lines = text.split("\n")
        colored = []
        for i, line in enumerate(lines):
            if line.startswith("usage:"):
                colored.append(f"[bold cyan]{line}[/]")
            elif line.strip() in HEADINGS:
                colored.append(f"\n[bold yellow]{line.strip()}[/]")
            elif line.startswith("  ") and "  " in line.strip() and not line.strip().startswith("--"):
                parts = line.split("  ", 1)
                colored.append(f"  [green]{parts[0].strip()}[/]  {parts[1].strip()}")
            else:
                colored.append(line)
        console.print(Panel(
            "\n".join(colored),
            title="[bold cyan]jusotscope[/]",
            border_style="cyan",
            width=80,
        ))

    def error(self, message):
        console.print(f"\n[bold red]✖[/] [red]{message}[/]")
        if "required" in message.lower():
            console.print("[dim]Tip: run [bold]jusotscope --help[/] for usage[/]")
        sys.exit(2)


def main():
    parser = _ColoredParser(
        prog="jusotscope",
        description="Unified offensive security toolkit - recon, scanning, AD, reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  jusotscope recon example.com
  jusotscope recon example.com --brute --json
  jusotscope recon 8.8.8.8
  jusotscope scan example.com
  jusotscope scan example.com -p 22,80,443 --json
  jusotscope ad enum 10.10.10.1 -d corp.local
  jusotscope ad enum 10.10.10.1 -d corp.local -u admin -p P@ssw0rd --json
        """,
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"jusotscope {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    from jusotscope.recon import cli as recon_cli
    recon_cli.register(subparsers)

    from jusotscope.scan import cli as scan_cli
    scan_cli.register(subparsers)

    from jusotscope.ad import cli as ad_cli
    ad_cli.register(subparsers)

    args = parser.parse_args()

    def handler(sig, frame):
        console.print("\n[red]Interrupted. Exiting.[/]")
        sys.exit(1)
    signal.signal(signal.SIGINT, handler)

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
