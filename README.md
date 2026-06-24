<div align="center">
<pre>
▄▄▄██▀▀▀█    ██   ██████  ▒█████ ▄▄▄█████▓  ██████  ▄████▄   ▒█████   ██▓███  ▓█████ 
   ▒██   ██  ▓██▒▒██    ▒ ▒██▒  ██▒▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒▓██░  ██▒▓█   ▀ 
   ░██  ▓██  ▒██░░ ▓██▄   ▒██░  ██▒▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒▓██░ ██▓▒▒███   
▓██▄██▓ ▓▓█  ░██░  ▒   ██▒▒██   ██░░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░▒██▄█▓▒ ▒▒▓█  ▄ 
 ▓███▒  ▒▒█████▓ ▒██████▒▒░ ████▓▒░  ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░░ ████▓▒░▒██▒ ░  ░░▒████▒
 ▒▓▒▒░  ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░   ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ▒▓▒░ ░  ░░░ ▒░ ░
 ▒ ░▒░  ░░▒░ ░ ░ ░ ░▒  ░ ░  ░ ▒ ▒░     ░    ░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░ ░▒ ░      ░ ░  ░
 ░ ░ ░   ░░░ ░ ░ ░  ░  ░  ░ ░ ░ ▒    ░      ░  ░  ░  ░        ░ ░ ░ ▒  ░░          ░   
 ░   ░     ░           ░      ░ ░                 ░  ░ ░          ░ ░              ░  ░
                                                     ░ 
</pre>

<p>
  <a href="https://github.com/jusot99/jusotscope/releases"><img src="https://img.shields.io/github/v/release/jusot99/jusotscope?style=for-the-badge&label=version&color=blue" alt="Version"></a>
  <a href="https://github.com/jusot99/jusotscope/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="https://github.com/jusot99/jusotscope/actions"><img src="https://img.shields.io/github/actions/workflow/status/jusot99/jusotscope/release.yml?style=for-the-badge&label=build" alt="Build"></a>
  <a href="https://github.com/jusot99/jusotscope"><img src="https://img.shields.io/github/stars/jusot99/jusotscope?style=for-the-badge&label=stars&color=yellow" alt="Stars"></a>
</p>

<p><b>recon · scan · ad enum · report</b></p>

<p>
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#install-from-source">Install</a>
</p>
</div>

## Features

| Category | Description |
|---|---|
| **DNS Reconnaissance** | Comprehensive DNS analysis, zone transfer testing, wildcard detection, CT log enumeration |
| **Subdomain Discovery** | Passive CT log enumeration and active brute-forcing with custom wordlists |
| **Security Assessment** | SPF/DMARC/DKIM checks, DNSSEC validation, takeover detection across 14 cloud providers |
| **Port Scanning** | Async TCP scanning with service identification and banner grabbing |
| **Active Directory Enumeration** | LDAP domain enumeration (users, groups, computers, SPNs, AS-REP, delegation, trusts) + SMB null session detection |
| **Reporting** | Rich terminal output, structured JSON, Markdown reports. Every subcommand supports `--json` and `-o report.md` |
| **IPv6 Ready** | Full dual-stack support for IPv4 and IPv6 targets |
| **Cross-Platform** | Linux, macOS, and Windows binaries |

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

> Pre-built binaries are on the [releases page](https://github.com/jusot99/jusotscope/releases).

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
- `dnspython` · `httpx` · `ldap3` · `rich`

## License

MIT — Built and maintained by [Jusot](https://github.com/jusot99).

---

⭐ Star the repo if you find it useful — it helps others discover it too.
