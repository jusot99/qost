# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

## Reporting a Vulnerability

This is an offensive security tool designed for authorized assessments **only**. If you find a security vulnerability:

1. **Do not** open a public GitHub issue.
2. Report it privately via GitHub's [Private Vulnerability Reporting](https://github.com/jusot99/qost/security/advisories/new).
3. Include steps to reproduce, affected versions, and any suggested fix if known.

You should receive a response within 72 hours. If you don't, please follow up.

## Scope

- Vulnerabilities in `qost` itself (e.g., command injection, credential leakage in logs).
- Unsafe default configurations or permissions.
- Supply chain risks from dependencies.

## Out of Scope

- Abusing the tool against targets without authorization — that's a legal matter, not a security bug.
- Known CVEs in third-party dependencies that are already patched by upgrading.
