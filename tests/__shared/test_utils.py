from unittest.mock import patch


from qost._shared.utils import is_ip, resolve_ip, resolve_all_ips


class TestIsIP:
    def test_valid_ipv4(self):
        assert is_ip("8.8.8.8") is True
        assert is_ip("192.168.1.1") is True
        assert is_ip("0.0.0.0") is True
        assert is_ip("255.255.255.255") is True

    def test_invalid_ipv4(self):
        assert is_ip("256.1.1.1") is False
        assert is_ip("192.168.1") is False
        assert is_ip("192.168.1.1.1") is False

    def test_valid_ipv6(self):
        assert is_ip("::1") is True
        assert is_ip("2001:db8::1") is True

    def test_hostnames(self):
        assert is_ip("example.com") is False
        assert is_ip("localhost") is False
        assert is_ip("") is False


class TestResolveIP:
    def test_resolve_success(self):
        with patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 0))]):
            result = resolve_ip("google.com")
            assert result == "8.8.8.8"

    def test_resolve_ip_passthrough(self):
        with patch("qost._shared.utils.is_ip", return_value=True):
            result = resolve_ip("8.8.8.8")
            assert result == "8.8.8.8"

    def test_resolve_failure(self):
        with patch("socket.getaddrinfo", side_effect=OSError("no address")):
            result = resolve_ip("nonexistent.invalid")
            assert result is None


class TestResolveAllIPs:
    def test_multiple_addresses(self):
        addrinfo = [
            (0, 0, 0, "", ("1.1.1.1", 0)),
            (0, 0, 0, "", ("2.2.2.2", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=addrinfo):
            result = resolve_all_ips("example.com")
            assert result == ["1.1.1.1", "2.2.2.2"]

    def test_empty_on_failure(self):
        with patch("socket.getaddrinfo", side_effect=OSError):
            result = resolve_all_ips("bad.example.com")
            assert result == []

    def test_resolves_ipv6(self):
        v6_addrinfo = [
            (10, 0, 0, "", ("2001:db8::1", 0, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=v6_addrinfo):
            result = resolve_all_ips("ipv6.example.com")
            assert "2001:db8::1" in result

    def test_resolves_both_v4_and_v6(self):
        addrinfo_v4 = [
            (2, 0, 0, "", ("1.1.1.1", 0)),
        ]
        addrinfo_v6 = [
            (10, 0, 0, "", ("2001:db8::1", 0, 0, 0)),
        ]

        def fake_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET:
                return addrinfo_v4
            if family == socket.AF_INET6:
                return addrinfo_v6
            return []

        import socket
        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            result = resolve_all_ips("dual.example.com")
            assert "1.1.1.1" in result
            assert "2001:db8::1" in result
