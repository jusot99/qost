import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qost.recon import cli


class TestRegister:
    def test_register_creates_parser(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["recon", "example.com"])
        assert args.target == "example.com"

    def test_register_defaults(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["recon", "example.com"])
        assert args.brute is False
        assert args.json_out is False
        assert args.silent is False
        assert args.verify is False


class TestRun:
    def test_run_invokes_async(self, recwarn):
        mock_ns = argparse.Namespace(
            target="example.com", brute=False, wordlist=None,
            silent=False, json_out=False, output=None,
            resolver=None, verify=False, file=None,
        )
        with patch("qost.recon.cli.asyncio.run") as mock_arun:
            mock_arun.side_effect = lambda coro: coro.close()
            cli.run(mock_ns)
            mock_arun.assert_called_once()
        recwarn.clear()

    @pytest.mark.asyncio
    async def test_run_resolves_target(self):
        mock_ns = argparse.Namespace(
            target="example.com", brute=False, wordlist=None,
            silent=True, json_out=False, output=None,
            resolver=None, verify=False, file=None,
        )
        with (
            patch("qost.recon.cli.utils.resolve_ip", return_value="1.2.3.4"),
            patch("qost.recon.cli.scanner.resolve_all", new=AsyncMock(return_value={})),
            patch("qost.recon.cli.security.check_spf_dmarc", new=AsyncMock(return_value=[])),
            patch("qost.recon.cli.subdomain.find_subdomains", new=AsyncMock(return_value=[])),
            patch("qost.recon.cli.portscan.scan", return_value=[]),
            patch("qost.recon.cli.enrich_asn", new=AsyncMock(return_value=None)),
            patch("qost.recon.cli.http_probe", new=AsyncMock(return_value={})),
            patch("qost.recon.cli.utils.resolve_all_ips", return_value=["1.2.3.4"]),
            patch("qost.recon.cli.ThreadPoolExecutor") as mock_pool,
            patch("qost.recon.cli.as_completed") as mock_ac,
        ):
            mock_future = MagicMock()
            mock_future.result.return_value = [("example.com", "1.2.3.4")]
            mock_pool.return_value.__enter__.return_value.submit.return_value = mock_future
            mock_ac.return_value = [mock_future]

            cli._DISABLE_VERIFY = True
            await cli._run(mock_ns)

    @pytest.mark.asyncio
    async def test_run_ip_target(self, recwarn):
        mock_ns = argparse.Namespace(
            target="8.8.8.8", brute=False, wordlist=None,
            silent=True, json_out=False, output=None,
            resolver=None, verify=False, file=None,
        )
        with (
            patch("qost.recon.cli.utils.get_ptr", return_value="dns.google"),
            patch("qost.recon.cli.scanner.resolve_all", return_value={}),
            patch("qost.recon.cli.portscan.scan", return_value=[]),
            patch("qost.recon.cli.enrich_asn", new=AsyncMock(return_value=None)),
            patch("qost.recon.cli.http_probe", new=AsyncMock(return_value={})),
            patch("qost.recon.cli.utils.resolve_all_ips", return_value=[]),
            patch("qost.recon.cli.ThreadPoolExecutor") as mock_pool,
            patch("qost.recon.cli.as_completed") as mock_ac,
        ):
            mock_future = MagicMock()
            mock_future.result.return_value = []
            mock_pool.return_value.__enter__.return_value.submit.return_value = mock_future
            mock_ac.return_value = [mock_future]

            cli._DISABLE_VERIFY = True
            await cli._run(mock_ns)
        recwarn.clear()
