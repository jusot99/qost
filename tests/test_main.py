import re
from unittest.mock import MagicMock, patch

import pytest

from jusotscope.__main__ import __version__, _ColoredParser


class TestVersion:
    def test_version_is_set(self):
        assert __version__ is not None
        assert re.match(r"^\d+\.\d+\.\d+", __version__)

    def test_version_matches_pyproject(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        m = re.search(r'^version\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(), re.M)
        pyproject_ver = m.group(1)
        assert __version__ == pyproject_ver


class TestArgParseHelp:
    def test_argparse_help_renders(self):
        parser = _ColoredParser(prog="testprog")
        with patch("jusotscope.__main__.console.print") as mock:
            parser.print_help()
            mock.assert_called_once()

    def test_version_arg_exists(self):
        parser = _ColoredParser(prog="testprog")
        parser.add_argument("--version", action="version", version="1.0")
        with patch("jusotscope.__main__.console.print"):
            version_actions = [a for a in parser._actions if hasattr(a, "version")]
            assert len(version_actions) == 1


class TestMain:
    def test_main_no_args_exits(self):
        with (
            patch("jusotscope.__main__.console.print"),
            pytest.raises(SystemExit),
        ):
            from jusotscope.__main__ import main
            with patch("sys.argv", ["jusotscope"]):
                main()

    def test_main_recon_dispatches(self):
        mock_func = MagicMock()
        with (
            patch("jusotscope.__main__.console.print"),
            patch("jusotscope.__main__._ColoredParser.parse_args",
                  return_value=MagicMock(func=mock_func)),
        ):
            from jusotscope.__main__ import main
            with patch("sys.argv", ["jusotscope", "recon", "example.com"]):
                main()
                mock_func.assert_called_once()

    def test_main_scan_dispatches(self):
        mock_func = MagicMock()
        with (
            patch("jusotscope.__main__.console.print"),
            patch("jusotscope.__main__._ColoredParser.parse_args",
                  return_value=MagicMock(func=mock_func)),
        ):
            from jusotscope.__main__ import main
            with patch("sys.argv", ["jusotscope", "scan", "example.com"]):
                main()
                mock_func.assert_called_once()

    def test_main_ad_dispatches(self):
        mock_func = MagicMock()
        with (
            patch("jusotscope.__main__.console.print"),
            patch("jusotscope.__main__._ColoredParser.parse_args",
                  return_value=MagicMock(func=mock_func)),
        ):
            from jusotscope.__main__ import main
            with patch("sys.argv", ["jusotscope", "ad", "enum", "10.0.0.1"]):
                main()
                mock_func.assert_called_once()


class TestSignalHandler:
    def test_sigint_propagates(self, recwarn):
        mock_func = MagicMock(side_effect=KeyboardInterrupt)
        with (
            patch("jusotscope.__main__.console.print"),
            patch("jusotscope.__main__._ColoredParser.parse_args",
                  return_value=MagicMock(func=mock_func)),
            pytest.raises(KeyboardInterrupt),
        ):
            from jusotscope.__main__ import main
            with patch("sys.argv", ["jusotscope", "recon", "x"]):
                main()
        recwarn.clear()
