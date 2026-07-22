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
- [x] Real HCL AST parser (`internal/parser/terraform`, built on `hashicorp/hcl/v2/hclsyntax`) — replaces the v0.1 regex/line scanner; only literal attribute values are captured, non-literal expressions (variable/resource references, function calls) are skipped rather than misparsed

## Phase 2 — Bicep + Kubernetes
- [x] Native Bicep parser (`internal/parser/bicep`) — a brace-depth scanner like the original Terraform v0.1 parser, no `bicep build`/ARM compilation step or external compiler dependency. ARM property names (e.g. `allowBlobPublicAccess`) are translated to the same canonical attribute keys Terraform's azurerm provider uses, so the existing Azure Rego pack evaluates Terraform and Bicep resources identically — see `armAttrKeyMap` in the parser and `internal/normalizer`'s `typeMap`
- [x] Kubernetes manifest parser (`internal/parser/k8s`) — flattens Pod and every pod-template controller kind (Deployment/DaemonSet/StatefulSet/ReplicaSet/Job/CronJob) to the same pod-security attribute shape, with a new `policies/k8s/pod-security` rule pack (PF-K8S-001..005: privileged containers, hostNetwork, privilege escalation, runAsNonRoot, missing resource limits). Helm chart parsing (rendering charts before scanning) is not yet implemented
- [x] Azure DevOps pipeline task (`integrations/azure-devops-task`) — installs PolicyForge, runs a scan, uploads SARIF as a build artifact, and gates the build on HIGH/CRITICAL findings, matching the GitHub Action
- [x] Custom policy authoring: `--policy-dir` loads user-supplied `.rego` files at scan time (`internal/engine/opa.go`'s `loadUserModules`), validated to declare a package under the `policyforge` namespace so their rules are actually discoverable

## Phase 3 — supply chain + enterprise
- [x] Sigstore/cosign artifact signing: `policyforge sign <file>` shells out to a user-installed `cosign` binary (`internal/signer`) rather than vendoring Sigstore's client libraries, keeping the CLI's own dependency footprint lean — install cosign separately to use it
- [x] SLSA provenance attestation: `policyforge scan --provenance <file>` emits a SLSA v0.2 predicate (`internal/provenance`) describing the scan (materials = scanned files by sha256 digest, invocation parameters, timestamps); `policyforge attest <file> --predicate <file>` attaches it as a signed in-toto attestation via `cosign attest-blob`
- [x] Drift detection against live Azure resources via Azure Resource Graph: `policyforge drift --subscription-id <id>` (`internal/drift`) queries Resource Graph for the same Azure resource types the Rego rule pack covers, authenticating via `azidentity.DefaultAzureCredential` (honors `az login`/env vars/managed identity — PolicyForge never handles Azure credentials itself), and diffs live ARM properties against declared IaC attributes using the same ARM-property-name mapping the Bicep parser already maintains (`bicep.CanonicalAttributes`)
- [ ] Enterprise module: hosted dashboard, Entra ID SSO, audit trail, compliance framework mapping (SOC2/PCI) — scoped in [`enterprise/DESIGN.md`](../enterprise/DESIGN.md); a throwaway **local prototype** of the ingestion API + dashboard exists at [`enterprise/portal`](../enterprise/portal) (own Go module, in-memory, no auth) wired to a new `scan --upload` CLI flag, proving the shape end to end — but the real product still needs the hosting-model/licensing-mechanics decisions in DESIGN.md's "Open questions" before anything here is production-real

## Contributing to the roadmap
Open an issue if you'd like to pick up any item above, or propose a new one. See [CONTRIBUTING.md](../CONTRIBUTING.md).
