import dns.resolver
import dns.query
import dns.zone
import dns.rdatatype

from jusotscope._shared.resolvers import DEFAULT_RESOLVERS
from jusotscope.recon.utils import is_ip


def query_records(domain: str, rtype: str, resolvers: list[str] | None = None):
    if is_ip(domain):
        if rtype == "A":
            return [domain], None
        return None, "IP address - no DNS records"

    resolvers = resolvers or DEFAULT_RESOLVERS
    res = dns.resolver.Resolver()
    res.timeout = 4
    res.lifetime = 8
    
    for rip in resolvers:
        try:
            res.nameservers = [rip]
            answers = res.resolve(domain, rtype, raise_on_no_answer=False)
            if answers.rrset is not None:
                return answers, None
        except Exception:
            continue
    return None, "All resolvers failed"


def resolve_all(target: str, resolvers: list[str] | None = None):
    resolvers = resolvers or DEFAULT_RESOLVERS
    results = {}
    types = [
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
        "SRV", "CAA", "SSHFP", "TLSA", "NAPTR", "DNSKEY", "DS",
    ]
    for rtype in types:
        answers, err = query_records(target, rtype, resolvers)
        results[rtype] = (answers, err)
    return results


def zone_transfer(ns: str, domain: str):
    if is_ip(domain):
        return None, "IP address"
    try:
        xfr = dns.query.xfr(ns, domain, timeout=8)
        zone = dns.zone.from_xfr(xfr)
        hosts = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    record_name = str(name) if str(name) != "@" else domain
                    hosts.append({
                        "name": f"{record_name}.{domain}" if record_name != domain else domain,
                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                        "data": str(rdata),
                    })
        return hosts, None
    except Exception as e:
        return None, str(e)


def _clean(s: str) -> str:
    return " ".join(s.split())


def format_rdata(rdata, rtype: str) -> str:
    if rtype == "MX":
        return _clean(f"{rdata.preference} {rdata.exchange}")
    if rtype == "TXT":
        return "".join(
            part.decode() if isinstance(part, bytes) else part
            for part in getattr(rdata, "strings", [])
        )
    if rtype == "SOA":
        return _clean(
            f"MNAME: {rdata.mname} | RNAME: {rdata.rname} | "
            f"Serial: {rdata.serial}"
        )
    if rtype == "SRV":
        return _clean(
            f"{rdata.target} {rdata.port} "
            f"(priority {rdata.priority}, weight {rdata.weight})"
        )
    if rtype == "CAA":
        return _clean(f"{rdata.flags} {rdata.tag} {rdata.value}")
    if rtype == "SSHFP":
        return _clean(f"Algorithm {rdata.algorithm} Type {rdata.fp_type} {rdata.fingerprint}")
    if rtype == "NAPTR":
        return _clean(
            f"{rdata.order} {rdata.preference} {rdata.flags} "
            f"{rdata.service} {rdata.regexp} {rdata.replacement}"
        )
    return _clean(str(getattr(rdata, "target", getattr(rdata, "address", rdata))))
