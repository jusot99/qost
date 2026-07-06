# Changelog

## 0.1.4 (2026-07-01)

### Added
- Full test suite: 171 tests across recon, scan, AD, shared modules
- CI pipeline: `tests.yml` (ruff + mypy + pytest on 3.10/3.11/3.12), `release.yml` (3 OS binaries)
- `QOST_RESOLVERS` env var to override DNS resolvers
- `verify` parameter to subdomain search functions (crtsh, AlienVault, RapidDNS)
- Package-data support for wordlists in pip-installed deployments

### Fixed
- SMB Direct TCP framing: 4-byte big-endian length prefix for port 445
- SMBv2 negotiate packet now matches smbclient format (single dialect 0x0210, credit 31)
- mypy errors: 8 → 0 (wrong imports of `is_ip`/`resolve_ip`)
- ruff errors: 8 → 0 (import ordering, bare except clauses, unused imports)
- `bare except Exception: pass` replaced with structured `logger.debug()` throughout
- Wordlist path uses `importlib.resources` ➜ works when installed via pip
- `_version.py` simplified and gitignored (generated at build time)

### Changed
- SMB null session check uses `socket.create_connection()` ➜ IPv4 + IPv6 support
- Release matrix: Linux, macOS ARM64, Windows x86_64

## 0.1.3 (2026-06-30)

### Added
- Initial release: reconnaissance, port scanning, AD enumeration, reporting
- subdomain discovery via crt.sh, AlienVault OTX, RapidDNS
- SMB null session detection (SMBv1 + SMBv2)
- LDAP domain enumeration (users, groups, computers, SPNs, AS-REP, delegation, trusts)
- Port scanning with banner grabbing
- JSON and Markdown report output
