# jusotscope

Unified offensive security toolkit, recon, scanning, AD, reporting.

Build and maintained by [Jusot](https://github.com/jusot99).

## Features

- **Reconnaissance**: Comprehensive DNS analysis, subdomain discovery, and security assessment.
  - Wildcard DNS detection to prevent false positives.
  - Certificate Transparency (CT) log searching and passive DNS integration.
  - Security checks for SPF, DMARC (correctly querying `_dmarc`), DNSSEC, and Subdomain Takeover.
  - HTTP probing (status, title, server) and ASN enrichment.
- **Port Scanning**: Fast, asynchronous port scanning with service detection and banner grabbing.
- **IPv6 Ready**: Full support for both IPv4 and IPv6 targets.
- **JSON Output**: Rich, structured output for easy integration with other tools and pipelines.
- **Cross-Platform**: Compatible with Linux, macOS, and Windows.

## Quick Start

```bash
pip install git+https://github.com/jusot99/jusotscope.git

# DNS Recon & Subdomain Discovery
jusotscope recon example.com --brute

# Port Scanning
jusotscope scan example.com -p 1-1000

# JSON Output for automation
jusotscope recon example.com --json > results.json
```

Or download a pre-built binary from [releases](https://github.com/jusot99/jusotscope/releases).

## Tools

| Command | Description |
|---------|-------------|
| `recon` | DNS recon, subdomain enumeration, security checks, and HTTP probing |
| `scan`  | Asynchronous port scanning and service detection |
| `ad`    | Active Directory assessment *(coming soon)* |
| `report`| Automated reporting and finding export *(coming soon)* |

## Install from source

```bash
git clone https://github.com/jusot99/jusotscope.git
cd jusotscope
pip install -e .
```

## Requirements

- Python >= 3.10
- dependencies: `dnspython`, `httpx`, `rich`

## License

MIT
