import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_dns_resolver():
    with patch("dns.resolver.Resolver") as mock:
        resolver = MagicMock()
        mock.return_value = resolver
        yield resolver


@pytest.fixture
def mock_httpx_client():
    """Async httpx client fixture that provides .get() etc."""
    client = AsyncMock()
    client.get = AsyncMock()
    client.__aenter__.return_value = client
    with patch("httpx.AsyncClient", return_value=client):
        yield client
