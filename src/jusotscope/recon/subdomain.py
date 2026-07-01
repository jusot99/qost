import asyncio
import logging
import re
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import resources
from pathlib import Path

import httpx

from jusotscope.recon.utils import is_ip, resolve_ip

logger = logging.getLogger(__name__)


async def crtsh_search(domain: str, verify: bool = True) -> list[str]:
    results = set()
    async with httpx.AsyncClient(timeout=15, verify=verify) as client:
        try:
            r = await client.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    for name in [entry.get("name_value", ""), entry.get("common_name", "")]:
                        for line in str(name).splitlines():
                            sub = line.strip().lower()
                            if not sub or sub.startswith("*") or domain not in sub:
                                continue
                            if re.match(r"^\d+[a-zA-Z]", sub):
                                continue
                            if "@" in sub:
                                sub = sub.split("@")[1]
                            if sub.endswith(f".{domain}") or sub == domain:
                                results.add(sub)
        except Exception as exc:
            logger.debug("crt.sh lookup failed for %s: %s", domain, exc)

        try:
            r = await client.get(
                f"https://tls.bufferover.run/dns?q=.{domain}",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                data = r.json()
                if "Results" in data:
                    for entry in data["Results"]:
                        if domain in entry.lower():
                            results.add(entry.split(",")[0].lower())
        except Exception as exc:
            logger.debug("TLS bufferover lookup failed for %s: %s", domain, exc)
    return sorted(results)


async def alienvault_search(domain: str, verify: bool = True) -> list[str]:
    results = set()
    async with httpx.AsyncClient(timeout=15, verify=verify) as client:
        try:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                for entry in r.json().get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname and hostname.endswith(f".{domain}"):
                        results.add(hostname.lower())
        except Exception as exc:
            logger.debug("AlienVault lookup failed for %s: %s", domain, exc)
    return sorted(results)


async def rapiddns_search(domain: str, verify: bool = True) -> list[str]:
    results = set()
    async with httpx.AsyncClient(timeout=15, verify=verify) as client:
        try:
            r = await client.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code == 200:
                for match in re.findall(
                    rf"<td>([\w.-]+\.{re.escape(domain)})</td>", r.text
                ):
                    results.add(match.lower())
        except Exception as exc:
            logger.debug("RapidDNS lookup failed for %s: %s", domain, exc)
    return sorted(results)


async def find_subdomains(target: str, verify: bool = True) -> list[str]:
    all_subs: set[str] = set()
    results = await asyncio.gather(
        crtsh_search(target, verify=verify),
        alienvault_search(target, verify=verify),
        rapiddns_search(target, verify=verify),
        return_exceptions=True
    )
    for res in results:
        if isinstance(res, list):
            for s in res:
                if re.match(r"^\d+[a-zA-Z]", s.split(".")[0]):
                    continue
                all_subs.add(s)
    return sorted(all_subs)


def brute_force(domain: str, wordlist_path: str | None = None) -> list[str]:
    if is_ip(domain):
        return []

    wildcard_ip = None
    r1 = f"wc-{uuid.uuid4().hex[:8]}.{domain}"
    r2 = f"wc-{uuid.uuid4().hex[:8]}.{domain}"
    ip1 = resolve_ip(r1)
    ip2 = resolve_ip(r2)
    if ip1 and ip1 == ip2:
        wildcard_ip = ip1

    _fallback_words = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "cpanel", "whm", "admin", "blog", "dev", "test", "api", "vpn",
        "localhost", "webdisk", "autodiscover", "ns3", "imap", "ns",
        "pop3", "www2", "forum", "ns4", "mail2", "mysql", "www1",
        "beta", "support", "store", "mx", "secure", "web", "app",
        "remote", "exchange", "owa", "cloud", "portal", "jenkins",
        "gitlab", "jira", "confluence", "git", "svn", "staging",
        "stage", "prod", "production", "backup", "db", "redis",
        "mongo", "kibana", "grafana", "prometheus", "monitor",
    ]

    def _load_words(path_hint: str | None) -> list[str]:
        if path_hint:
            p = Path(path_hint)
            try:
                loaded = [line.strip() for line in p.read_text().splitlines() if line.strip()]
                if loaded:
                    return loaded
            except OSError:
                logger.debug("Wordlist not found at %s, using fallback", path_hint)
        try:
            ref = resources.files("jusotscope") / "wordlists" / "subdomains.txt"
            loaded = [line.strip() for line in ref.read_text().splitlines() if line.strip()]
            if loaded:
                return loaded
        except (OSError, ModuleNotFoundError):
            pass
        return _fallback_words

    words = _load_words(wordlist_path)

    found: list[str] = []

    def check(sub: str) -> str | None:
        subdomain = f"{sub}.{domain}"
        try:
            ip = resolve_ip(subdomain)
            if not ip:
                return None
            if wildcard_ip and ip == wildcard_ip:
                if sub.lower() == "www":
                    return subdomain
                return None
            return subdomain
        except (socket.gaierror, OSError):
            return None


    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(check, w): w for w in words}
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
    return found
