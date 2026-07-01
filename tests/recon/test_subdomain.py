from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qost.recon.subdomain import crtsh_search, alienvault_search, rapiddns_search, find_subdomains


def _mock_response(**kwargs):
    """Synchronous mock HTTP response."""
    m = MagicMock()
    for k, v in kwargs.items():
        setattr(m, k, v)
    m.status_code = 200
    return m


@pytest.mark.asyncio
class TestCrtshSearch:
    async def test_returns_subdomains(self, mock_httpx_client):
        mock_response = _mock_response(
            json=lambda: [{"name_value": "sub.example.com\nanother.example.com"}],
        )
        mock_httpx_client.get.return_value = mock_response

        results = await crtsh_search("example.com")
        assert "sub.example.com" in results
        assert "another.example.com" in results

    async def test_handles_http_error(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = Exception("HTTP error")
        results = await crtsh_search("example.com")
        assert results == []

    async def test_empty_response(self, mock_httpx_client):
        mock_response = _mock_response(json=lambda: [])
        mock_httpx_client.get.return_value = mock_response

        results = await crtsh_search("example.com")
        assert results == []


@pytest.mark.asyncio
class TestAlienvaultSearch:
    async def test_returns_subdomains(self, mock_httpx_client):
        mock_response = _mock_response(
            json=lambda: {"passive_dns": [{"hostname": "sub.example.com"}]},
        )
        mock_httpx_client.get.return_value = mock_response

        results = await alienvault_search("example.com")
        assert "sub.example.com" in results

    async def test_handles_error(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = Exception("API error")
        results = await alienvault_search("example.com")
        assert results == []


@pytest.mark.asyncio
class TestRapidDNSSearch:
    async def test_returns_subdomains(self, mock_httpx_client):
        mock_response = _mock_response(
            text="<table><tr><td>sub1.example.com</td></tr><tr><td>sub2.example.com</td></tr></table>",
        )
        mock_httpx_client.get.return_value = mock_response

        results = await rapiddns_search("example.com")
        assert "sub1.example.com" in results
        assert "sub2.example.com" in results

    async def test_handles_parse_error(self, mock_httpx_client):
        mock_response = _mock_response(text="not html")
        mock_httpx_client.get.return_value = mock_response

        results = await rapiddns_search("example.com")
        assert results == []


@pytest.mark.asyncio
class TestFindSubdomains:
    async def test_aggregates_all_sources(self):
        with (
            patch("qost.recon.subdomain.crtsh_search", new=AsyncMock(return_value=["a.example.com"])),
            patch("qost.recon.subdomain.alienvault_search", new=AsyncMock(return_value=["b.example.com"])),
            patch("qost.recon.subdomain.rapiddns_search", new=AsyncMock(return_value=["c.example.com"])),
        ):
            results = await find_subdomains("example.com")
            assert len(results) == 3
            assert "a.example.com" in results
            assert "b.example.com" in results
            assert "c.example.com" in results

    async def test_deduplicates(self):
        with (
            patch("qost.recon.subdomain.crtsh_search", new=AsyncMock(return_value=["a.example.com", "a.example.com"])),
            patch("qost.recon.subdomain.alienvault_search", new=AsyncMock(return_value=[])),
            patch("qost.recon.subdomain.rapiddns_search", new=AsyncMock(return_value=[])),
        ):
            results = await find_subdomains("example.com")
            assert len(results) == 1
            assert "a.example.com" in results
