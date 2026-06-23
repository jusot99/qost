import re
from pathlib import Path

_pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
_m = re.search(r'^version\s*=\s*"([^"]+)"', _pyproject.read_text(), re.M)
__version__ = _m.group(1) if _m else "0.0.0"
