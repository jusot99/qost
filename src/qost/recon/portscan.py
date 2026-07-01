import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (993, "IMAPS"), (995, "POP3S"),
    (2082, "cPanel"), (2083, "cPanel SSL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (27017, "MongoDB"), (9200, "Elasticsearch"),
]


def scan(host: str) -> list[tuple[int, str]]:
    open_ports: list[tuple[int, str]] = []

    def check(port_info: tuple[int, str]) -> tuple[int, str] | None:
        port, svc = port_info
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            r = s.connect_ex((host, port))
            s.close()
            return (port, svc) if r == 0 else None
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(check, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            r = f.result()
            if r:
                open_ports.append(r)

    return sorted(open_ports)
