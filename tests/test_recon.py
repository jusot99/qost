from jusotscope.recon.utils import is_ip, resolve_ip


def test_is_ip():
    assert is_ip("8.8.8.8") is True
    assert is_ip("example.com") is False
    assert is_ip("notanip") is False


def test_resolve_ip():
    ip = resolve_ip("example.com")
    assert ip is not None
    assert isinstance(ip, str)
