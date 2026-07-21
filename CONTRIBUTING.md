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

- **Add a policy rule.** Rules are real `.rego` files under `policies/<provider>/<pack>/`, embedded into the binary at build time — no Go changes needed. Each `deny[msg]` rule should be paired with a `severity["PF-XXX-NNN"] = "..."` entry in the same package (see `policies/azure/cis-foundations` for examples), and a test fixture in `examples/`.
- **Improve the Terraform parser.** `internal/parser/terraform` is intentionally simple (regex-based) in v0.1. Help is welcome moving it toward a real HCL AST parser.
- **Bicep support.** `internal/parser/bicep` is currently an empty package waiting for a first implementation — see the roadmap for the intended ARM JSON compilation approach.
- **Kubernetes support.** Same story for `internal/parser/k8s` — planned for Phase 2.
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
