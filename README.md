# PolicyForge

**Open-source policy-as-code scanner for Terraform, Bicep, and Kubernetes — with Azure treated as a first-class citizen, not an afterthought.**

Most IaC scanners are Terraform/CloudFormation-first and treat Bicep/ARM as a second-class format. PolicyForge flips that: Bicep and Azure Policy alignment get full support, alongside Terraform and (from Phase 2) Kubernetes manifests. It also generates a lightweight SBOM on every scan as a first step toward supply-chain visibility.

> **Status:** v0.1 (early scaffold). The CLI runs end-to-end today against Terraform with a native Go rule set; OPA/Rego evaluation and Bicep support are next. See [`docs/roadmap.md`](docs/roadmap.md).

## Quick start

```bash
git clone https://github.com/chethankumblekar/policyforge.git
cd policyforge
go build -o policyforge ./cmd/policyforge

./policyforge scan --path ./examples --format table
```

Example output:

```
RULE       SEVERITY   RESOURCE                                 LOCATION
PF-AZ-001  HIGH       example                                  examples/insecure.tf:1
           Storage account allows public blob access
PF-AZ-010  CRITICAL   allow_all_inbound                        examples/insecure.tf:11
           NSG rule allows unrestricted inbound access

4 finding(s).
```

Other output formats:

```bash
./policyforge scan --path ./examples --format sarif > results.sarif
./policyforge scan --path ./examples --format json
./policyforge scan --path ./examples --sbom
```

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
| PF-AZ-001 | `azurerm_storage_account` | Public blob access disabled | CIS Azure Foundations 3.6 |
| PF-AZ-002 | `azurerm_storage_account` | TLS 1.2 minimum enforced | CIS Azure Foundations 3.1 |
| PF-AZ-010 | `azurerm_network_security_group_rule` | No unrestricted inbound rules | CIS Azure Foundations 6.1/6.2 |
| PF-AZ-020 | `azurerm_key_vault` | Purge protection enabled | Data-loss prevention best practice |

More rules and AWS coverage are on the roadmap — see [Contributing](CONTRIBUTING.md) if you'd like to add one.

## CI/CD integration

- **GitHub Actions:** see [`integrations/github-action`](integrations/github-action) — uploads SARIF straight into GitHub code scanning.
- **Azure DevOps:** pipeline task coming in the next milestone.

## Project layout

```
cmd/policyforge/        CLI entrypoint
internal/parser/        Terraform (v0.1), Bicep + K8s (planned)
internal/normalizer/     Unified resource model
internal/engine/         Policy evaluation + SARIF/JSON/table rendering
internal/sbom/           SBOM generation
policies/                Rego rule packs (reference implementation for Phase 1)
integrations/            CI/CD glue (GitHub Action, Azure DevOps task)
examples/                Sample IaC files for demoing scans
```

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for the phased plan — real OPA/Rego evaluation, Bicep parsing, Kubernetes support, drift detection, and the enterprise dashboard tier.

## License

Apache 2.0 — see [LICENSE](LICENSE). Core scanner, rule packs, and CI/CD integrations are and will remain fully open source. An optional enterprise tier (hosted dashboard, SSO, audit trail, SLA support) is planned as a separately licensed add-on — see `enterprise/README.md`.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
