import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_importlib():
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
    pyproject_ver = m.group(1)

    from importlib.metadata import version
    installed_ver = version("jusotscope")

    assert pyproject_ver == installed_ver, (
        f"pyproject.toml says {pyproject_ver} but installed package is {installed_ver}. "
        "Run: pip install -e ."
    )


def test_version_is_semver():
    from jusotscope.__main__ import __version__
    assert re.match(r"^\d+\.\d+\.\d+$", __version__), f"Invalid semver: {__version__}"


def test_version_not_fallback():
    from jusotscope.__main__ import __version__
    assert __version__ != "0.0.0", "Version fell back to 0.0.0 — metadata missing?"
