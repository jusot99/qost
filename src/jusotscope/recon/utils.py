import socket

from jusotscope._shared.utils import is_ip, resolve_all_ips, resolve_ip  # noqa: F401


def get_ptr(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
