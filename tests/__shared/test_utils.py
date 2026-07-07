from unittest.mock import patch


from qost._shared.utils import (
    expand_targets,
    is_ip,
    iter_targets,
    resolve_all_ips,
    resolve_ip,
)


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


class TestExpandTargets:
    def test_single_target(self):
        assert expand_targets(["example.com"]) == ["example.com"]

    def test_comma_separated(self):
        assert expand_targets(["a.com,b.com"]) == ["a.com", "b.com"]

    def test_cidr_small(self):
        hosts = expand_targets(["127.0.0.0/30"])
        assert "127.0.0.1" in hosts
        assert "127.0.0.2" in hosts
        assert len(hosts) == 2

    def test_cidr_invalid(self):
        assert expand_targets(["not-a-cidr/33"]) == []

    def test_empty_skipped(self):
        assert expand_targets(["", "a.com"]) == ["a.com"]

    def test_mixed(self):
        result = expand_targets(["example.com", "10.0.0.0/31,test.local"])
        assert "example.com" in result
        assert "test.local" in result


class TestIterTargets:
    def test_no_target_no_file(self):
        assert iter_targets(None) == []

    def test_from_file(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n# comment\ntest.local\n")
        result = iter_targets(None, str(f))
        assert "example.com" in result
        assert "test.local" in result

    def test_file_overrides_positional(self):
        assert iter_targets("ignored.com", "/nonexistent/file") == ["ignored.com"]

    def test_string_target(self):
        assert iter_targets("single.com") == ["single.com"]

    def test_list_target(self):
        assert iter_targets(["a.com", "b.com"]) == ["a.com", "b.com"]
