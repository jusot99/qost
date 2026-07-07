<div align="center">
<pre>
  █████   ▒█████    ██████ ▄▄▄█████▓
▒██▓  ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒  ██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
░██  █▀ ░▒██   ██░  ▒   ██▒░ ▓██▓ ░
░▒███▒█▄ ░ ████▓▒░▒██████▒▒  ▒██▒ ░
░░ ▒▒░ ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
 ░ ▒░  ░   ░ ▒ ▒░ ░ ░▒  ░ ░    ░
   ░   ░ ░ ░ ░ ▒  ░  ░  ░    ░
    ░        ░ ░        ░

</pre>

<p>
  <a href="https://github.com/jusot99/qost/releases"><img src="https://img.shields.io/github/v/release/jusot99/qost?style=for-the-badge&label=version&color=blue" alt="Version"></a>
  <a href="https://github.com/jusot99/qost/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="https://github.com/jusot99/qost/actions"><img src="https://img.shields.io/github/actions/workflow/status/jusot99/qost/release.yml?style=for-the-badge&label=build" alt="Build"></a>
  <a href="https://github.com/jusot99/qost"><img src="https://img.shields.io/github/stars/jusot99/qost?style=for-the-badge&label=stars&color=yellow" alt="Stars"></a>
</p>

<p><b>recon · scan · ad enum · report</b></p>

<p>
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#install-from-source">Install</a>
</p>
</div>

> [!CAUTION]
> This tool is for **authorized security assessments only**. Ensure you have **explicit permission** before targeting any system.

## Features

| Category | Description |
|---|---|
| **DNS Reconnaissance** | Comprehensive DNS analysis, zone transfer testing, wildcard detection, CT log enumeration |
| **Subdomain Discovery** | Passive CT log enumeration and active brute-forcing with custom wordlists |
| **Security Assessment** | SPF/DMARC/DKIM checks, DNSSEC validation, takeover detection across 14 cloud providers |
| **Port Scanning** | Async TCP scanning with service ID, banner grabbing, TLS cert extraction, and HTTP probe |
| **Active Directory Enumeration** | LDAP enumeration (users, groups, computers, SPNs, trusts, AS-REP, delegation, RBCD, AD CS, LAPS, gMSA) + SMB signing + LDAP channel binding + SMB null session |
| **Reporting** | Rich terminal output, structured JSON, Markdown reports. Every subcommand supports `--json` and `-o report.md` |
| **IPv6 Ready** | Full dual-stack support for IPv4 and IPv6 targets |
| **Cross-Platform** | Linux, macOS, and Windows binaries |

## Quick Start

> [!TIP]
> Grab a **pre-built binary** from the [releases page](https://github.com/jusot99/qost/releases) if you don't want to install Python.

```bash
pip install git+https://github.com/jusot99/qost.git

# DNS reconnaissance with subdomain brute-forcing
qost recon example.com --brute

# Multi-target / CIDR / file input
qost recon 10.0.0.1,10.0.0.2
qost recon 10.0.0.0/24
qost recon -f targets.txt

# Port scan with TLS cert extraction and HTTP probe
qost scan example.com -p 1-1000
qost scan 10.10.10.1 -p 80,443,8443 --json

# Active Directory enumeration (anonymous)
qost ad enum 10.10.10.1 -d corp.local

# Active Directory enumeration (authenticated) ➜ full checks
qost ad enum 10.10.10.1 -d corp.local -u admin -p P@ssw0rd

# Export results as JSON or Markdown
qost recon example.com --json
qost recon example.com -o report.md
```

> [!NOTE]
> Results can be exported as **JSON** (`--json`) or **Markdown** (`-o report.md`) for integration with other tools or report generation.

## Commands

| Command | Description |
|---------|-------------|
| `recon` | DNS reconnaissance (async, 14 record types), subdomain enumeration, security assessment (SPF/DMARC/DKIM/DNSSEC), zone transfer, CT logs |
| `scan`  | Async port scanning with service ID, banner grab, TLS cert CN/SAN extraction, HTTP probe (Server header) |
| `ad enum` | LDAP enumeration: users, SPNs, AS-REP, delegation (U/C/RBCD), AD CS (ESC1), LAPS, gMSA, SMB signing, LDAP channel binding, SMB null session |

## Options

All subcommands support these global flags:

| Flag | Description |
|------|-------------|
| `--json`, `-j` | Output results as structured JSON |
| `--output`, `-o` | Write report to file (Markdown or JSON) |
| `--silent`, `-s` | Suppress terminal output |

## Install from Source

```bash
git clone https://github.com/jusot99/qost.git
cd qost
pip install -e .
```

## Requirements

- Python 3.10 or later
- `dnspython` · `httpx` · `ldap3` · `rich`

## License

MIT

---

> [!TIP]
> **Star the repo** ⭐ if you find it useful ➜ it helps others discover it too.
