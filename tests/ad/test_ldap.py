

from jusotscope.ad.enum import _decode, _safe, _safe_list, Finding, EnumResult


class TestDecode:
    def test_bytes(self):
        assert _decode(b"hello") == "hello"

    def test_string(self):
        assert _decode("hello") == "hello"

    def test_list(self):
        assert _decode(["a", b"b"]) == "a, b"

    def test_int(self):
        assert _decode(42) == "42"


class TestSafe:
    def test_safe_string(self):
        assert _safe({"name": "alice"}, "name") == "alice"

    def test_safe_bytes(self):
        assert _safe({"name": b"alice"}, "name") == "alice"

    def test_safe_list(self):
        assert _safe({"name": [b"alice"]}, "name") == "alice"

    def test_safe_missing(self):
        assert _safe({}, "name") == ""


class TestSafeList:
    def test_list_of_bytes(self):
        assert _safe_list({"members": [b"a", b"b"]}, "members") == ["a", "b"]

    def test_single_string(self):
        assert _safe_list({"members": "a"}, "members") == ["a"]

    def test_empty(self):
        assert _safe_list({}, "members") == []


class TestFinding:
    def test_creation(self):
        f = Finding(type="test", severity="HIGH", detail="desc", fix="fix it")
        assert f.type == "test"
        assert f.severity == "HIGH"

    def test_defaults(self):
        f = Finding(type="x", severity="LOW", detail="y", fix="z")
        assert f.severity == "LOW"


class TestEnumResult:
    def test_defaults(self):
        r = EnumResult()
        assert r.target == ""
        assert r.users == []
        assert r.groups == []
        assert r.findings == []

    def test_smb_check_import(self):
        from jusotscope.ad.smb import check_null_session
        assert callable(check_null_session)
