# jusotscope

Unified offensive security toolkit for reconnaissance, port scanning, Active Directory enumeration, and reporting.

Built and maintained by [Jusot](https://github.com/jusot99).

## Features

- **DNS Reconnaissance** — Comprehensive DNS analysis (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, SSHFP, TLSA, NAPTR, DNSKEY, DS), zone transfer testing, wildcard DNS detection, and Certificate Transparency log enumeration.
- **Subdomain Discovery** — Passive enumeration via CT logs and active brute-forcing with custom wordlists.
- **Security Assessment** — SPF/DMARC/DKIM misconfiguration checks, DNSSEC validation, subdomain takeover detection across 14 cloud providers.
- **Port Scanning** — Asynchronous TCP scanning with service identification and banner grabbing. Top 50 ports by default, custom port ranges supported.
- **Active Directory Enumeration** — LDAP-based domain enumeration (users, groups, computers, SPNs, AS-REP roastable accounts, delegation, trusts) with raw SMB null session detection.
- **Reporting** — Terminal output via Rich, structured JSON exports, and Markdown reports. Every subcommand supports `--json` and `--output report.md`.
- **IPv6 Ready** — Full dual-stack support for both IPv4 and IPv6 targets.
- **Cross-Platform** — Linux, macOS, and Windows binaries available.

## Quick Start

```bash
pip install git+https://github.com/jusot99/jusotscope.git

# DNS reconnaissance with subdomain brute-forcing
jusotscope recon example.com --brute

# Port scan a range
jusotscope scan example.com -p 1-1000

# Active Directory enumeration (anonymous)
jusotscope ad enum 10.10.10.1 -d corp.local

# Active Directory enumeration (authenticated)
jusotscope ad enum 10.10.10.1 -d corp.local -u admin -p P@ssw0rd

# Export results as JSON or Markdown
jusotscope recon example.com --json
jusotscope recon example.com -o report.md
```

Pre-built binaries are available on the [releases page](https://github.com/jusot99/jusotscope/releases).

## Commands

| Command | Description |
|---------|-------------|
| `recon` | DNS reconnaissance, subdomain enumeration, and security assessment |
| `scan`  | Asynchronous port scanning with service and banner detection |
| `ad enum` | Active Directory LDAP enumeration and SMB null session testing |

## Options

All subcommands support these global flags:

| Flag | Description |
|------|-------------|
| `--json`, `-j` | Output results as structured JSON |
| `--output`, `-o` | Write report to file (Markdown or JSON) |
| `--silent`, `-s` | Suppress terminal output |

## Install from Source

```bash
git clone https://github.com/jusot99/jusotscope.git
cd jusotscope
pip install -e .
```

## Requirements

- Python 3.10 or later
- Dependencies: `dnspython`, `httpx`, `ldap3`, `rich`

## License

MIT
