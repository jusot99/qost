import ipaddress
import socket

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def resolve_ip(host: str) -> str | None:
    if is_ip(host):
        return host
    try:
        addrs = socket.getaddrinfo(host, None)
        if addrs:
            return addrs[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None

def resolve_all_ips(host: str) -> list[str]:
    if is_ip(host):
        return [host]
    ips: list[str] = []
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addrs = socket.getaddrinfo(host, None, family=family)
                for a in addrs:
                    ip = a[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except (socket.gaierror, OSError):
                continue
    except Exception:
        pass
    return ips
