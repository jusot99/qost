import asyncio
import socket

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 587, 593,
    636, 993, 995, 1080, 1194, 1433, 1521, 2049, 2082, 2083,
    2181, 2375, 2376, 3128, 3306, 3389, 5060, 5222, 5432, 5601,
    5900, 6379, 8080, 8081, 8443, 8888, 9092, 9200, 27017, 27018,
]

BANNER_SIZE = 2048

SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 593: "RPC",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker TLS", 3128: "Squid",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5222: "XMPP",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8081: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9092: "Kafka",
    9200: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB",
}


def parse_ports(port_spec: str) -> list[int]:
    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_i, end_i = int(start.strip()), int(end.strip())
                ports.update(range(start_i, end_i + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(ports)


from jusotscope._shared.utils import is_ip, resolve_ip as resolve_host


def service_name(port: int) -> str:
    name = SERVICE_MAP.get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port) or ""
    except (OSError, socket.error):
        return ""


async def check_port(
    host: str, port: int, timeout: float = 3.0
) -> dict:
    result: dict = {
        "port": port,
        "state": "closed",
        "service": service_name(port),
        "banner": "",
    }
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        result["state"] = "open"
        try:
            reader = _
            banner = await asyncio.wait_for(
                reader.read(BANNER_SIZE), timeout=1.5
            )
            text = banner.decode(errors="replace").strip()
            if text:
                result["banner"] = text[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except (TimeoutError, asyncio.TimeoutError, ConnectionRefusedError,
            ConnectionResetError, OSError):
        pass
    return result


async def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 3.0,
    concurrency: int = 50,
) -> list[dict]:
    ip = resolve_host(host)
    if not ip:
        return []

    sem = asyncio.Semaphore(concurrency)

    async def _check(p: int) -> dict:
        async with sem:
            return await check_port(ip, p, timeout)

    tasks = [_check(p) for p in ports]
    results = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
    results.sort(key=lambda r: r["port"])
    return results
