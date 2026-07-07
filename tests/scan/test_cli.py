import argparse
from unittest.mock import AsyncMock, patch

import pytest

from qost.scan import cli


class TestRegister:
    def test_register_creates_parser(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["scan", "example.com"])
        assert args.target == "example.com"

    def test_register_defaults(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["scan", "example.com"])
        assert args.timeout == 3.0
        assert args.concurrency == 50
        assert args.json_out is False
        assert args.silent is False


class TestRun:
    def test_run_invokes_async(self, recwarn):
        mock_ns = argparse.Namespace(
            target="example.com", ports=None,
            silent=False, json_out=False, output=None,
            timeout=3.0, concurrency=50, file=None,
        )
        with patch("qost.scan.cli.asyncio.run") as mock_arun:
            mock_arun.side_effect = lambda coro: coro.close()
            cli.run(mock_ns)
            mock_arun.assert_called_once()
        recwarn.clear()

    @pytest.mark.asyncio
    async def test_run_resolves_host(self, recwarn):
        mock_ns = argparse.Namespace(
            target="example.com", ports=None,
            silent=True, json_out=False, output=None,
            timeout=3.0, concurrency=50,
        )
        with (
            patch("qost.scan.cli.resolve_host", return_value="1.2.3.4"),
            patch("qost.scan.cli.scan_ports", new=AsyncMock(return_value=[])),
        ):
            await cli._run(mock_ns)
        recwarn.clear()

    @pytest.mark.asyncio
    async def test_run_unresolvable(self):
        mock_ns = argparse.Namespace(
            target="nonexistent.invalid", ports=None,
            silent=True, json_out=False, output=None,
            timeout=3.0, concurrency=50,
        )
        with (
            patch("qost.scan.cli.resolve_host", return_value=None),
            patch("qost.scan.cli.console.print") as mock_print,
        ):
            await cli._run(mock_ns)
            mock_print.assert_called_once_with("[red]Could not resolve:[/] nonexistent.invalid")
