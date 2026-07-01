import argparse
from unittest.mock import MagicMock, patch


from jusotscope.ad import cli


class TestRegister:
    def test_register_creates_parser(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["ad", "enum", "10.0.0.1", "-d", "corp.local"])
        assert args.target == "10.0.0.1"
        assert args.domain == "corp.local"

    def test_register_defaults(self):
        parser = argparse.ArgumentParser(prog="test")
        subs = parser.add_subparsers()
        cli.register(subs)
        args = parser.parse_args(["ad", "enum", "10.0.0.1", "-d", "corp.local"])
        assert args.username is None
        assert args.password is None
        assert args.json_out is False
        assert args.silent is False


class TestRunEnum:
    def test_run_enum_anonymous(self):
        mock_result = MagicMock()
        mock_result.duration_seconds = 0.0
        mock_result.null_session = {"status": "secure", "detail": "no access"}

        with (
            patch("jusotscope.ad.cli.enum_domain", return_value=mock_result),
            patch("jusotscope.ad.cli.check_null_session", return_value={"status": "secure", "detail": "no access"}),
        ):
            ns = argparse.Namespace(
                target="10.0.0.1", domain="corp.local",
                username=None, password=None,
                json_out=False, silent=True, output=None,
            )
            cli.run_enum(ns)

    def test_run_enum_outputs_json(self):
        mock_result = MagicMock()
        mock_result.duration_seconds = 0.5
        mock_result.null_session = {"status": "secure", "detail": "no access"}
        mock_result.findings = []
        mock_result.root_dse = {}

        with (
            patch("jusotscope.ad.cli.enum_domain", return_value=mock_result),
            patch("jusotscope.ad.cli.check_null_session", return_value={"status": "secure", "detail": "no access"}),
            patch("jusotscope.ad.cli.json.dumps") as mock_dumps,
        ):
            ns = argparse.Namespace(
                target="10.0.0.1", domain="corp.local",
                username="admin", password="P@ssw0rd",
                json_out=True, silent=True, output=None,
            )
            cli.run_enum(ns)
            mock_dumps.assert_called_once()
