# Contributing to PolicyForge

Thanks for considering a contribution. PolicyForge is early-stage, so there's a lot of room to shape the project's direction.

## Getting started

```bash
git clone https://github.com/chethankumblekar/policyforge.git
cd policyforge
go build ./...
go test ./...
```

## Ways to contribute

- **Add a policy rule.** Rules are real `.rego` files under `policies/<provider>/<pack>/`, embedded into the binary at build time — no Go changes needed. Each `deny[msg]` rule should be paired with a `severity["PF-XXX-NNN"] = "..."` entry in the same package (see `policies/azure/cis-foundations` for examples), and a test fixture in `examples/`. You can also try out a new rule without a fork at all via `policyforge scan --policy-dir <dir>` — see the root [README](README.md#custom-policy-authoring).
- **Terraform parser.** `internal/parser/terraform` is a real HCL v2 AST parser (`hashicorp/hcl/v2/hclsyntax`); it only captures literal attribute values today (no variable interpolation or function evaluation) — extending that resolution is welcome.
- **Bicep parser.** `internal/parser/bicep` is a native brace-depth scanner (no `bicep build`/ARM compilation step) that translates ARM property names to the same canonical attribute keys Terraform's azurerm provider uses. Adding more ARM resource type mappings (`armAttrKeyMap`) is a good first contribution.
- **Kubernetes parser.** `internal/parser/k8s` flattens Pod-template workloads to a pod-security attribute shape; Helm chart rendering (compiling a chart to manifests before scanning) isn't implemented yet.
- **Documentation and examples.** Real-world insecure/secure IaC snippets in `examples/` make the project easier to trust and easier to test against.

## Pull request guidelines

1. Open an issue first for anything beyond a small fix, so we can agree on direction before you invest time.
2. Include tests for new parser logic or policy rules.
3. Run `go vet ./...` and `go test ./...` before submitting.
4. Keep PRs scoped to one change — easier to review, easier to merge.

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the technical merits of a change. Anything not covered here follows the [Contributor Covenant](https://www.contributor-covenant.org/).

## License

By contributing, you agree your contributions will be licensed under the project's Apache 2.0 license (see [LICENSE](LICENSE)).
