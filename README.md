# PolicyForge

**Open-source policy-as-code scanner for Terraform, Bicep, Kubernetes, and Helm — with Azure treated as a first-class citizen, not an afterthought.**

Most IaC scanners are Terraform/CloudFormation-first and treat Bicep/ARM as a second-class format. PolicyForge flips that: Bicep and Azure Policy alignment get full support, alongside Terraform, Kubernetes manifests, and Helm charts — the Azure Rego rule pack evaluates Terraform and Bicep resources identically, since both parsers normalize to the same canonical attribute names. It also generates a lightweight SBOM on every scan as a first step toward supply-chain visibility.

> **Status:** v0.1. The CLI runs end-to-end against Terraform, Bicep, Kubernetes manifests, and Helm charts, evaluating real OPA/Rego rule packs (embedded into the binary at build time). See [`docs/roadmap.md`](docs/roadmap.md).

## Quick start

```bash
git clone https://github.com/chethankumblekar/policyforge.git
cd policyforge
go build -o policyforge ./cmd/policyforge

./policyforge scan --path ./examples --format table
```

`./examples` has fixtures for every supported language (Terraform, Bicep, Kubernetes, Helm) — a scan of the whole directory runs every parser and rule pack together. Helm charts are rendered via a locally installed `helm template` before scanning (install [Helm](https://helm.sh/docs/intro/install/) to enable this — if it's missing, PolicyForge just warns and skips any charts it finds rather than failing the whole scan):

```
RULE       SEVERITY   RESOURCE                                 LOCATION
PF-AWS-001 HIGH       logs                                     examples/insecure-aws.tf:1
           S3 bucket "logs" uses public-read ACL
PF-AZ-001  HIGH       example                                  examples/insecure.tf:1
           storage account "example" allows public blob access (CIS 3.6)
PF-AZ-001  HIGH       examplestorage                           examples/insecure.bicep:1
           storage account "examplestorage" allows public blob access (CIS 3.6)
PF-K8S-001 CRITICAL   Deployment/insecure-app                  examples/insecure-k8s.yaml:1
           "Deployment/insecure-app" runs a privileged container
PF-K8S-001 CRITICAL   Deployment/insecure-helm-app             examples/insecure-helm-chart/templates/deployment.yaml:1
           "Deployment/insecure-helm-app" runs a privileged container
...
21 finding(s).
```

Other output formats and options:

```bash
./policyforge scan --path ./examples --format sarif > results.sarif
./policyforge scan --path ./examples --format json
./policyforge scan --path ./examples --sbom
./policyforge scan --path ./examples --policy-dir ./my-org-policies  # merge in custom .rego rules
```

## Custom policy authoring

Point `--policy-dir` at a directory of your own `.rego` files to merge them in alongside the embedded rule packs — no fork or rebuild required. Each file must declare a package under the `policyforge` namespace (e.g. `package policyforge.custom.naming`) and a `deny[msg]` rule; an optional `severity["YOUR-RULE-ID"] = "..."` mapping controls the finding's severity (defaults to `HIGH`). Files outside that namespace are rejected at load time with an explanation, since PolicyForge only discovers rules nested under `data.policyforge`.

## Supply chain: signing, provenance, and drift detection

```bash
# Sign a scan artifact (needs cosign installed: https://docs.sigstore.dev/cosign/installation)
./policyforge scan --path ./examples --format json > results.json
./policyforge sign --key cosign.key --bundle results.bundle.json results.json

# Emit a SLSA provenance predicate for the scan, then attach it as a signed attestation
./policyforge scan --path ./examples --format json --provenance provenance.json > results.json
./policyforge attest --key cosign.key --predicate provenance.json --bundle results.attest.bundle.json results.json

# Compare declared IaC config against live Azure state (uses whatever Azure credentials
# you already have — az login, environment variables, managed identity)
./policyforge drift --path ./examples --subscription-id <your-subscription-id>
```

`sign`/`attest` shell out to a `cosign` binary you install separately (no Sigstore client libraries are vendored into PolicyForge itself — see `internal/signer`), so cosign's own version and flags govern the exact behavior; `--bundle` is required by modern cosign (v3+) and records a Rekor transparency log entry, so it needs network access to `rekor.sigstore.dev` even when signing with a local key. `drift` only compares the Azure resource types the Rego rule pack already understands, and only attributes your IaC source actually declares — it won't invent an opinion about configuration you never specified.

## Enterprise portal (self-hosted)

`--upload` sends a scan's findings to a running instance of the self-hosted dashboard under [`enterprise/portal`](enterprise/portal): a Go API (SQLite-persisted, HTTP Basic Auth for the ingestion API, real per-user login via OIDC/Entra ID SSO if you configure it) plus a [Next.js dashboard](enterprise/portal/web) with its own distinctive design system, both Docker/Compose-packaged:

```bash
cd enterprise/portal && PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=secret docker compose up -d   # in one terminal
policyforge scan --path ./examples --upload http://admin:secret@localhost:8090 --org acme --project infra-repo   # in another
```

Open `http://localhost:3000` (browser will prompt for the same credentials, or your IdP's login if you've set `OIDC_*` — see `enterprise/portal/README.md`) to see the scan list and drill into findings, including SBOM/provenance attestation status (`--sbom`/`--provenance`, if passed), an audit log of every ingestion and login, and a `/compliance` page rolling up findings into SOC2/PCI control coverage. This is a real, if still early, implementation of the self-hosted enterprise tier scoped in [`enterprise/DESIGN.md`](enterprise/DESIGN.md) — org-wide policy management is the one item still ahead of it.

## How it works

```
IaC files (Terraform / Bicep / K8s / Helm)
        │
        ▼
   Parser layer  →  Normalizer (unified resource model)  →  Policy engine  →  Findings
                                                                    │
                                                                    ▼
                                                    SARIF / JSON / table output
                                                    + optional SBOM generation
```

See the full architecture diagram and design rationale in the project plan under `docs/`.

## Current rule coverage (v0.1)

| Rule ID | Resource | Check | Maps to |
|---|---|---|---|
| PF-AZ-001 | `azurerm_storage_account` / `Microsoft.Storage/storageAccounts` | Public blob access disabled | CIS Azure Foundations 3.6 |
| PF-AZ-002 | `azurerm_storage_account` / `Microsoft.Storage/storageAccounts` | TLS 1.2 minimum enforced | CIS Azure Foundations 3.1 |
| PF-AZ-010 | `azurerm_network_security_group_rule` / `Microsoft.Network/.../securityRules` | No unrestricted inbound rules | CIS Azure Foundations 6.1/6.2 |
| PF-AZ-020 | `azurerm_key_vault` / `Microsoft.KeyVault/vaults` | Purge protection enabled | Data-loss prevention best practice |
| PF-AWS-001 | `aws_s3_bucket` | No `public-read`/`public-read-write` canned ACL | AWS S3 security best practice |
| PF-AWS-010 | `aws_security_group_rule` | No unrestricted ingress from `0.0.0.0/0` | AWS security group best practice |
| PF-K8S-001 | Pod / Deployment / DaemonSet / StatefulSet / ReplicaSet / Job / CronJob | No privileged containers | Kubernetes Pod Security Standards (Baseline) |
| PF-K8S-002 | *(same, any pod-template workload)* | No `hostNetwork` | Kubernetes Pod Security Standards (Baseline) |
| PF-K8S-003 | *(same)* | No `allowPrivilegeEscalation` | Kubernetes Pod Security Standards (Restricted) |
| PF-K8S-004 | *(same)* | No explicit `runAsNonRoot: false` | Kubernetes Pod Security Standards (Restricted) |
| PF-K8S-005 | *(same)* | Containers declare resource limits | Reliability best practice |

The PF-AZ-* rules are the same Rego files whether the resource came from Terraform or Bicep — each parser normalizes to a shared canonical type and attribute set. All rules live under [`policies/`](policies) — see [Contributing](CONTRIBUTING.md) if you'd like to add one, or `--policy-dir` above to add your own without a fork.

## CI/CD integration

- **GitHub Actions:** see [`integrations/github-action`](integrations/github-action) — uploads SARIF straight into GitHub code scanning.
- **Azure DevOps:** see [`integrations/azure-devops-task`](integrations/azure-devops-task) — installs PolicyForge, runs a scan, and publishes SARIF results as a build artifact.

## Project layout

```
cmd/policyforge/        CLI entrypoint
internal/parser/        Terraform, Bicep, Kubernetes, Helm parsers + the shared Resource type
internal/normalizer/     Unified resource model
internal/engine/         OPA/Rego policy evaluation + SARIF/JSON/table rendering
internal/sbom/           SBOM generation
internal/signer/         cosign CLI wrapper (sign/attest)
internal/provenance/     SLSA provenance predicate generation
internal/drift/          Azure Resource Graph client + declared-vs-live comparison
policies/                Rego rule packs, embedded into the binary at build time
integrations/            CI/CD glue (GitHub Action, Azure DevOps task)
examples/                Sample IaC files for demoing scans
enterprise/              Design doc for the planned hosted/enterprise tier (nothing built yet)
```

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for the phased plan and what's left — the real, production enterprise dashboard tier is the largest open item.

## License

Apache 2.0 — see [LICENSE](LICENSE). Core scanner, rule packs, and CI/CD integrations are and will remain fully open source. An optional enterprise tier (hosted dashboard, SSO, audit trail, SLA support) is planned as a separately licensed add-on — see [`enterprise/DESIGN.md`](enterprise/DESIGN.md).

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
