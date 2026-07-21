# PolicyForge

**Open-source policy-as-code scanner for Terraform, Bicep, and Kubernetes — with Azure treated as a first-class citizen, not an afterthought.**

Most IaC scanners are Terraform/CloudFormation-first and treat Bicep/ARM as a second-class format. PolicyForge flips that: Bicep and Azure Policy alignment get full support, alongside Terraform and Kubernetes manifests — the Azure Rego rule pack evaluates Terraform and Bicep resources identically, since both parsers normalize to the same canonical attribute names. It also generates a lightweight SBOM on every scan as a first step toward supply-chain visibility.

> **Status:** v0.1. The CLI runs end-to-end against Terraform, Bicep, and Kubernetes manifests, evaluating real OPA/Rego rule packs (embedded into the binary at build time). See [`docs/roadmap.md`](docs/roadmap.md).

## Quick start

```bash
git clone https://github.com/chethankumblekar/policyforge.git
cd policyforge
go build -o policyforge ./cmd/policyforge

./policyforge scan --path ./examples --format table
```

`./examples` has fixtures for all three supported languages (Terraform, Bicep, Kubernetes) — a scan of the whole directory runs every parser and rule pack together:

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
...
16 finding(s).
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

## How it works

```
IaC files (Terraform / Bicep / K8s)
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
internal/parser/        Terraform, Bicep, Kubernetes parsers + the shared Resource type
internal/normalizer/     Unified resource model
internal/engine/         OPA/Rego policy evaluation + SARIF/JSON/table rendering
internal/sbom/           SBOM generation
policies/                Rego rule packs, embedded into the binary at build time
integrations/            CI/CD glue (GitHub Action, Azure DevOps task)
examples/                Sample IaC files for demoing scans
```

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for the phased plan — real OPA/Rego evaluation, Bicep parsing, Kubernetes support, drift detection, and the enterprise dashboard tier.

## License

Apache 2.0 — see [LICENSE](LICENSE). Core scanner, rule packs, and CI/CD integrations are and will remain fully open source. An optional enterprise tier (hosted dashboard, SSO, audit trail, SLA support) is planned as a separately licensed add-on — see `enterprise/README.md`.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
