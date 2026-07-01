import os

_ENV_VAR = "JUSOTSCOPE_RESOLVERS"
_FALLBACK = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def _parse_resolvers(value: str) -> list[str] | None:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return parts if parts else None


def get_resolvers() -> list[str]:
    raw = os.environ.get(_ENV_VAR)
    if raw:
        parsed = _parse_resolvers(raw)
        if parsed:
            return parsed
    return _FALLBACK


DEFAULT_RESOLVERS = get_resolvers()
