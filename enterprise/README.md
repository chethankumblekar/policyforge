# Enterprise

This directory holds the enterprise tier: a self-hosted dashboard today, with org-wide policy management, an audit trail, compliance framework mapping (SOC2/PCI), and Entra ID SSO planned on top of it.

See [`DESIGN.md`](DESIGN.md) for full scope. Two calls are made and built on: **self-hosted** (you run it; no PolicyForge-operated SaaS) and **network-gated access** (a shared Basic Auth credential, not license keys or per-user accounts yet).

[`portal/`](portal) is the real (if still early) implementation: an ingestion API + dashboard, SQLite-persisted, Docker/Compose-packaged, HTTP Basic Auth-gated — wired to the OSS CLI's `scan --upload` flag. It's a separate Go module; the OSS CLI build doesn't depend on it. See `portal/README.md` to run it.

This directory's boundary keeps the open-source core (everything outside it) and any future paid features cleanly separated, per the licensing model in the root [README](../README.md). Community support for the OSS core happens via GitHub issues. Enterprise support (SLA-backed) is planned as a separate offering as the product matures.
