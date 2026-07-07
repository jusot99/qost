# Changelog

## 0.1.5 (2026-07-07)

### Added
- Async DNS resolver ➜ all 14 record types resolved concurrently via `asyncio.to_thread` + `asyncio.gather`
- Multi-target / CIDR / file input ➜ `--file`/`-f` flag on `recon` and `scan`, CIDR expansion (`10.0.0.0/24`), comma-separated targets
- AD CS enumeration ➜ LDAP search for CA servers (`pKIEnrollmentService`) + certificate templates with ESC1 flag (`ENROLLEE_SUPPLIES_SUBJECT`)
- Constrained delegation & RBCD ➜ `msDS-AllowedToDelegateTo` / `msDS-AllowedToActOnBehalfOfOtherIdentity` detection
- LAPS password detection ➜ `ms-Mcs-AdmPwd` / `msLAPS-Password` readable check (graceful if attribute missing from schema)
- gMSA account detection ➜ `msDS-GroupManagedServiceAccount` enumeration
- SMB signing validation ➜ signing-required flag extracted from SMBv2 negotiate response `SecurityMode` bit 1
- LDAP channel binding detection ➜ `supportedCapabilities` OID `1.2.840.113556.1.4.800`/`801` check
- Active service probing ➜ TLS certificate CN/SAN extraction + HTTP GET probe (`Server` header) in `scan`
- CLI display for all new AD fields (constrained delegation, RBCD, AD CS, templates, LAPS, gMSA, SMB signing, LDAP channel binding)
- JSON/Markdown report includes all new fields in `security` block and per-check entries
- Tests: 189 total (+18 new: async DNS, multi-target, CIDR, AD delegation/ADCS/LAPS/gMSA/SMB signing)

### Fixed
- `LDAPAttributeError` crash when LAPS attributes absent from AD schema ➜ caught in `_search()` helper
- SMBv2 `signing_required` extraction aligned with SMBv1-fallback control flow

### Changed
- `query_records`/`resolve_all` in `recon/scanner.py` are now `async` ➜ all callers/tests updated
- `check_null_session` in `ad/smb.py` returns `signing_required` key in all result dicts
- `EnumResult` dataclass extended with 8 new fields: `constrained`, `rbcd`, `adcs_servers`, `adcs_templates`, `laps_computers`, `gmsa_accounts`, `smb_signing`, `ldap_channel_binding`

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
