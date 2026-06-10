import argparse
import signal
import sys

from jusotscope._shared.output import console


def main():
    parser = argparse.ArgumentParser(
        prog="jusotscope",
        description="Unified offensive security toolkit — recon, scanning, AD, reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jusotscope recon example.com
  jusotscope recon example.com --brute --json
  jusotscope recon 8.8.8.8
        """,
    )
    parser.add_argument(
        "--version", "-V", action="version", version="jusotscope 0.1.0"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Register modules
    from jusotscope.recon import __main__ as recon_main
    recon_main.register(subparsers)

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
