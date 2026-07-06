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

> [!TIP]
> **Enable Private Vulnerability Reporting** in your repo settings to let researchers submit reports directly through the GitHub UI.

## Scope

- Vulnerabilities in `qost` itself (e.g., command injection, credential leakage in logs)
- Unsafe default configurations or permissions
- Supply chain risks from dependencies

## Out of Scope

> [!WARNING]
> **Abusing this tool against targets without authorization** is a legal matter, not a security bug. This will not be treated as a valid report.

- Known CVEs in third-party dependencies that are already patched by upgrading
