# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it, and the impact you think it has. I aim to acknowledge reports within 7 days.

## Supported versions

Only the latest release receives security fixes.

## Security model

Sitrep treats feed content, AI output and the UI itself as untrusted. The full threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and what has been tested is in [docs/SECURITY_TESTING.md](docs/SECURITY_TESTING.md).

## Verifying downloads

Installers are built by GitHub Actions from the tagged source (see `.github/workflows/release.yml`). Download only from this repository's Releases page. The installer is not yet code-signed, so Windows SmartScreen will show a warning.
