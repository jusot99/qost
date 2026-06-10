import socket


def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def get_ptr(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
