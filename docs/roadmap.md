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
- [x] `internal/engine/opa.go` written — real Rego evaluation via `EvaluateOPA`, gated behind the `opa` build tag until dependencies are fetched on a machine with unrestricted internet (`go get github.com/open-policy-agent/opa/rego@v0.70.0`, then `go build -tags opa ./...`)
- [ ] Swap `cmd/policyforge/main.go` to call `EvaluateOPA` by default and remove the `opa` build tag
- [ ] Load rule packs dynamically from `policies/` at runtime instead of hardcoding
- [ ] Add rule severity as Rego metadata instead of the TODO'd hardcoded `SeverityHigh` in `opa.go`
- [ ] Expand CIS Azure Foundations coverage beyond the 4 seed rules
- [ ] Add core AWS rule pack (S3, security groups)
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
