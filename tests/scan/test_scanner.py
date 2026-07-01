from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from jusotscope.scan.scanner import (
    parse_ports,
    service_name,
    check_port,
    scan_ports,
    DEFAULT_PORTS,
    SERVICE_MAP,
)


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_multiple_ports(self):
        assert parse_ports("80,443,8080") == [80, 443, 8080]

    def test_port_range(self):
        assert parse_ports("80-82") == [80, 81, 82]

    def test_mixed(self):
        assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

    def test_empty(self):
        assert parse_ports("") == []

    def test_garbage_skipped(self):
        assert parse_ports("abc,80,def-ghi") == [80]

    def test_invalid_range(self):
        assert parse_ports("80-") == []


class TestServiceName:
    def test_well_known(self):
        assert service_name(22) == "SSH"
        assert service_name(80) == "HTTP"
        assert service_name(443) == "HTTPS"

    def test_unknown(self):
        with patch("socket.getservbyport", side_effect=OSError):
            assert service_name(99999) == ""

    def test_mapped_but_unregistered(self):
        assert SERVICE_MAP[3389] == "RDP"


@pytest.mark.asyncio
class TestCheckPort:
    async def _make_conn_pair(self, reader_data=None):
        """Create (reader, writer) pair for async connection mocks."""
        reader = AsyncMock()
        reader.read.return_value = reader_data if reader_data is not None else b""
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        return (reader, writer)

    async def test_open_port(self):
        conn_pair = await self._make_conn_pair(b"SSH-2.0-OpenSSH_8.9p1")
        with patch("asyncio.open_connection", return_value=conn_pair):
            result = await check_port("192.168.1.1", 22)
            assert result["state"] == "open"
            assert "OpenSSH" in result["banner"]

    async def test_closed_port(self):
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await check_port("192.168.1.1", 23)
            assert result["state"] == "closed"

    async def test_timeout(self):
        with patch("asyncio.open_connection", side_effect=TimeoutError):
            result = await check_port("192.168.1.1", 81)
            assert result["state"] == "closed"

    async def test_no_banner(self):
        conn_pair = await self._make_conn_pair()
        conn_pair[0].read.side_effect = TimeoutError
        with patch("asyncio.open_connection", return_value=conn_pair):
            result = await check_port("192.168.1.1", 80)
            assert result["state"] == "open"
            assert result["banner"] == ""

    async def test_read_timeout_still_reports_open(self):
        conn_pair = await self._make_conn_pair()
        conn_pair[0].read.side_effect = TimeoutError
        with patch("asyncio.open_connection", return_value=conn_pair):
            result = await check_port("192.168.1.1", 443)
            assert result["state"] == "open"
            assert result["banner"] == ""


@pytest.mark.asyncio
class TestScanPorts:
    async def test_scan_multiple_ports(self):
        with (
            patch("jusotscope.scan.scanner.resolve_host", return_value="8.8.8.8"),
            patch("asyncio.open_connection", side_effect=ConnectionRefusedError),
        ):
            results = await scan_ports("8.8.8.8", [22, 80, 443])
            assert len(results) == 3
            assert all(r["state"] == "closed" for r in results)

    async def test_scan_unresolvable(self):
        with patch("jusotscope.scan.scanner.resolve_host", return_value=None):
            results = await scan_ports("nonexistent.invalid", [80])
            assert results == []

    async def test_mixed_results(self):
        async def fake_open_conn(host, port):
            if port == 22:
                reader = AsyncMock()
                reader.read.return_value = b"SSH-2.0"
                writer = MagicMock()
                writer.wait_closed = AsyncMock()
                return (reader, writer)
            raise ConnectionRefusedError

        with (
            patch("jusotscope.scan.scanner.resolve_host", return_value="10.0.0.1"),
            patch("asyncio.open_connection", new=fake_open_conn),
        ):
            results = await scan_ports("10.0.0.1", [22, 80])
            assert len(results) == 2
            open_ports = [r for r in results if r["state"] == "open"]
            assert len(open_ports) == 1
            assert open_ports[0]["port"] == 22


class TestConstants:
    def test_default_ports(self):
        assert len(DEFAULT_PORTS) > 0

    def test_service_map(self):
        assert SERVICE_MAP[22] == "SSH"
        assert SERVICE_MAP[80] == "HTTP"
