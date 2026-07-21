# Roadmap

## v0.1 — current
- [x] Repo scaffold, Go module, CI skeleton
- [x] Terraform parser (regex-based, dependency-free)
- [x] Unified normalizer model
- [x] Native Go rule evaluation (4 seed rules: PF-AZ-001/002/010/020)
- [x] Table / JSON / SARIF output
- [x] Minimal SBOM generation
- [x] GitHub Action integration

## Phase 1 — real policy engine
- [x] `internal/engine/opa.go` — real Rego evaluation via `EvaluateOPA`, now a default dependency (`github.com/open-policy-agent/opa/rego`), no build tag required
- [x] `cmd/policyforge/main.go` calls `engine.Evaluate` (OPA-backed) by default; the v0.1 native Go rule set has been removed in favor of Rego
- [x] Rule packs are embedded at build time (`policies/embed.go`, `policies.FS`) and discovered dynamically by walking the `data.policyforge` result tree — no package names hardcoded in Go, so new packs under `policies/` need no code changes
- [x] Rule severity is declared per-pack as Rego metadata (a `severity[ruleID] = "..."` partial object alongside each `deny` rule), read by `internal/engine/opa.go` instead of a hardcoded `SeverityHigh`
- [x] Expanded CIS Azure Foundations coverage: NSG (PF-AZ-010) and Key Vault (PF-AZ-020) now live as real Rego rules alongside storage account (PF-AZ-001/002)
- [x] Core AWS rule pack added (`policies/aws/core`): S3 public-ACL check (PF-AWS-001), security group unrestricted ingress (PF-AWS-010)
- [ ] Real HCL AST parser (replace regex-based Terraform parser)

## Phase 2 — Bicep + Kubernetes
- [ ] Bicep → ARM JSON compilation step, native Bicep parser
- [ ] Kubernetes manifest + Helm chart parser
- [ ] Azure DevOps pipeline task (parity with the GitHub Action)
- [ ] Custom policy authoring: user-supplied `.rego` files validated against a schema

## Phase 3 — supply chain + enterprise
- [ ] Sigstore/cosign artifact signing
- [ ] SLSA provenance attestation
- [ ] Drift detection against live Azure resources via Azure Resource Graph
- [ ] Enterprise module: hosted dashboard, Entra ID SSO, audit trail, compliance framework mapping (SOC2/PCI)

## Contributing to the roadmap
Open an issue if you'd like to pick up any item above, or propose a new one. See [CONTRIBUTING.md](../CONTRIBUTING.md).
