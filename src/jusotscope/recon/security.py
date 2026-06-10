from dataclasses import dataclass, field

from jusotscope.recon.scanner import query_records
from jusotscope.recon.utils import resolve_ip


CLOUD_TARGETS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "azure.com": "Azure",
    "azurewebsites.net": "Azure App Service",
    "blob.core.windows.net": "Azure Blob",
    "s3.amazonaws.com": "AWS S3",
    "herokuapp.com": "Heroku",
    "heroku.com": "Heroku",
    "firebaseio.com": "Firebase",
    "netlify.app": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "vercel.app": "Vercel",
    "trafficmanager.net": "Azure Traffic Manager",
}

DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2", "dkim",
    "mail", "mta", "zoho", "protonmail", "mx",
]


@dataclass
class Vuln:
    type: str
    severity: str
    detail: str
    fix: str


def check_spf_dmarc(domain: str, txt_records: list[str]) -> list[Vuln]:
    vulns: list[Vuln] = []

    spf_found = False
    for txt in txt_records:
        t = txt.lower()
        if "v=spf1" in t:
            spf_found = True
            if "+all" in t:
                vulns.append(Vuln(
                    "Weak SPF Policy", "HIGH",
                    "Allows email spoofing from any server",
                    "Change +all to ~all or -all",
                ))
            elif "?all" in t:
                vulns.append(Vuln(
                    "Neutral SPF Policy", "MEDIUM",
                    "Email authentication not enforced",
                    "Change ?all to ~all",
                ))

    if not spf_found:
        vulns.append(Vuln(
            "Missing SPF Record", "MEDIUM",
            "Email spoofing possible",
            "Add SPF: v=spf1 mx ~all",
        ))

    dmarc_found = any("v=dmarc" in t for t in txt_records)
    if not dmarc_found:
        vulns.append(Vuln(
            "Missing DMARC Record", "MEDIUM",
            "No email authentication policy",
            "Add DMARC: v=DMARC1; p=none; rua=mailto:admin@domain",
        ))

    dkim_found = False
    for sel in DKIM_SELECTORS:
        answers, _ = query_records(f"{sel}._domainkey.{domain}", "TXT")
        if answers:
            dkim_found = True
            break

    if not dkim_found:
        vulns.append(Vuln(
            "No DKIM Record Found", "LOW",
            "Email signing not detected",
            "Configure DKIM signing for your mail provider",
        ))

    return vulns


def check_dnssec(dnskey_records: list[str], ds_records: list[str]) -> list[Vuln]:
    vulns: list[Vuln] = []
    if dnskey_records:
        vulns.append(Vuln(
            "DNSSEC Enabled", "INFO",
            "Domain has DNSSEC signing keys",
            "Ensure keys are rotated regularly",
        ))
    else:
        vulns.append(Vuln(
            "DNSSEC Not Detected", "LOW",
            "Domain is not DNSSEC signed",
            "Consider enabling DNSSEC to prevent spoofing",
        ))

    if ds_records:
        vulns.append(Vuln(
            "DS Records Found", "INFO",
            "Chain of trust configured",
            "Verify DS matches current DNSKEY",
        ))
    return vulns


def check_takeover(cname_records: list[str]) -> list[Vuln]:
    vulns: list[Vuln] = []
    for cname in cname_records:
        target = cname.rstrip(".")
        for cloud_domain, provider in CLOUD_TARGETS.items():
            if cloud_domain in target:
                try:
                    resolve_ip(target)
                except Exception:
                    vulns.append(Vuln(
                        "Subdomain Takeover Possible", "HIGH",
                        f"CNAME to {provider} ({target}) but service not provisioned",
                        "Remove the dangling CNAME or provision the service",
                    ))
    return vulns
