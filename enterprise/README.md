# Enterprise (planned)

This directory holds the future enterprise tier: hosted dashboard, Entra ID SSO for the tool itself, org-wide policy management, audit trail, and compliance framework mapping (SOC2/PCI).

See [`DESIGN.md`](DESIGN.md) for the scope/architecture sketch and the open product decisions (hosting model, licensing mechanics) still blocking a real implementation.

[`portal/`](portal) is a runnable **local prototype** of the ingestion API + dashboard — not the real product (no auth, no persistence, no license gating), but enough to see the `/api/scans` shape and dashboard UX working end to end with the OSS CLI's `scan --upload` flag. It's a separate Go module; the OSS CLI build doesn't depend on it.

This directory's boundary keeps the open-source core (everything outside it) and any future paid features cleanly separated, per the licensing model in the root [README](../README.md). Community support for the OSS core happens via GitHub issues. Enterprise support (SLA-backed) is planned as a separate offering once the real product exists.
