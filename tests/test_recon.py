from jusotscope.recon.utils import is_ip, resolve_ip


def test_is_ip():
    assert is_ip("8.8.8.8") is True
    assert is_ip("2001:4860:4860::8888") is True
    assert is_ip("example.com") is False
    assert is_ip("notanip") is False


def test_resolve_ip():
    # Test IPv4/Dual-stack
    ip = resolve_ip("google.com")
    assert ip is not None
    assert isinstance(ip, str)
    
    # Test IPv6 (if available on system, this should still pass or return None if failed)
    # We can at least check it doesn't crash
    ip_v6 = resolve_ip("ipv6.google.com")
    if ip_v6:
        assert isinstance(ip_v6, str)
