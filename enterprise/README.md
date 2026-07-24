# Enterprise

This directory holds the enterprise tier: a self-hosted dashboard with real per-user login, an audit trail, and SOC2/PCI compliance control coverage today, plus org-wide policy management planned on top of it.

See [`DESIGN.md`](DESIGN.md) for full scope. Calls made and built on: **self-hosted** (you run it; no PolicyForge-operated SaaS), **network-gated API access** (a shared Basic Auth credential for `/api/scans`, not license keys), and **OIDC/Entra ID SSO** for real per-user dashboard login.

[`portal/`](portal) is the real (if still early) implementation: an ingestion API + dashboard, SQLite-persisted, Docker/Compose-packaged, HTTP Basic Auth for the API, OIDC SSO for the dashboard — wired to the OSS CLI's `scan --upload` flag. It's a separate Go module; the OSS CLI build doesn't depend on it. See `portal/README.md` to run it and configure SSO.

This directory's boundary keeps the open-source core (everything outside it) and any future paid features cleanly separated, per the licensing model in the root [README](../README.md). Community support for the OSS core happens via GitHub issues. Enterprise support (SLA-backed) is planned as a separate offering as the product matures.
