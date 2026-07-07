import ipaddress
import socket
from pathlib import Path



def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _cidr_hosts(network: str) -> list[str]:
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        return []


def expand_targets(targets: list[str]) -> list[str]:
    """Expand a list of target specs into flat list of target strings.
    
    Supports:
    - Single domain/IP
    - CIDR notation (192.168.1.0/24)
    - Comma-separated (example.com,10.0.0.1)
    """
    expanded: list[str] = []
    for t in targets:
        for part in t.split(","):
            part = part.strip()
            if not part:
                continue
            if "/" in part:
                expanded.extend(_cidr_hosts(part))
            else:
                expanded.append(part)
    return expanded


def iter_targets(args_target: str | list[str] | None, args_file: str | None = None) -> list[str]:
    """Build target list from CLI args and optional file.
    
    Order: --file targets > positional target(s). Not both.
    """
    if args_file:
        try:
            lines = Path(args_file).read_text().splitlines()
            raw = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
            return expand_targets(raw)
        except OSError:
            pass
    if args_target is None:
        return []
    if isinstance(args_target, list):
        return expand_targets(args_target)
    return expand_targets([args_target])

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
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            addrs = socket.getaddrinfo(host, None, family=family)
            for a in addrs:
                ip = a[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError):
            continue
    return ips
