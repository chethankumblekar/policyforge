// Package signer wraps the cosign CLI so PolicyForge can sign scan
// artifacts and attach SLSA provenance attestations to them, without
// vendoring Sigstore's client libraries (Fulcio/Rekor/KMS clients) into
// what is otherwise a lean, single-binary tool with no external Go
// dependencies for this feature. cosign must be installed and on PATH —
// see https://docs.sigstore.dev/cosign/installation.
package signer

import (
	"fmt"
	"os/exec"
)

// cosignBinary is the executable name looked up on PATH. It's a var
// (rather than a const) so tests can point it at a stub script instead of
// a real cosign install.
var cosignBinary = "cosign"

// RequireCosign reports whether the cosign binary is available, with an
// error that includes install guidance if not.
func RequireCosign() error {
	if _, err := exec.LookPath(cosignBinary); err != nil {
		return fmt.Errorf("cosign not found on PATH — install it from https://docs.sigstore.dev/cosign/installation to use sign/attest: %w", err)
	}
	return nil
}

// SignOptions configures a SignBlob call. Key selects a local key file,
// KMS URI (e.g. "azurekms://...", "awskms://...") or is left empty for
// Sigstore's keyless (Fulcio/Rekor) flow, which requires an interactive
// or CI OIDC identity. Bundle is the output path for cosign's combined
// signature+certificate verification bundle (`--bundle`) — modern cosign
// (v3+) requires this rather than the older separate
// --output-signature/--output-certificate flags.
type SignOptions struct {
	Key    string
	Bundle string
}

func (o SignOptions) args(path string) []string {
	args := []string{"sign-blob", "--yes"}
	if o.Key != "" {
		args = append(args, "--key", o.Key)
	}
	if o.Bundle != "" {
		args = append(args, "--bundle", o.Bundle)
	}
	return append(args, path)
}

// SignBlob signs path via `cosign sign-blob` and returns cosign's stdout
// (the base64-encoded signature, if Bundle wasn't set). Note: cosign's
// bundle format records a transparency log entry with the public Rekor
// instance by default, so this requires network access to
// rekor.sigstore.dev even when signing with a local key.
func SignBlob(path string, opts SignOptions) (string, error) {
	if err := RequireCosign(); err != nil {
		return "", err
	}

	out, err := exec.Command(cosignBinary, opts.args(path)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cosign sign-blob failed: %w\n%s", err, out)
	}
	return string(out), nil
}

// AttestOptions configures an AttestBlob call. Like SignOptions.Bundle,
// modern cosign (v3+) requires Bundle to produce a verifiable attestation
// (it records a Rekor transparency log entry as part of the bundle, so
// this needs network access to rekor.sigstore.dev even with a local key).
type AttestOptions struct {
	Key               string
	PredicatePath     string
	PredicateType     string // e.g. "slsaprovenance", or a custom predicate type URI
	Bundle            string
	OutputAttestation string
}

func (o AttestOptions) args(path string) []string {
	args := []string{"attest-blob", "--yes", "--predicate", o.PredicatePath}
	if o.PredicateType != "" {
		args = append(args, "--type", o.PredicateType)
	}
	if o.Key != "" {
		args = append(args, "--key", o.Key)
	}
	if o.Bundle != "" {
		args = append(args, "--bundle", o.Bundle)
	}
	if o.OutputAttestation != "" {
		args = append(args, "--output-attestation", o.OutputAttestation)
	}
	return append(args, path)
}

// AttestBlob attaches a predicate (e.g. a SLSA provenance predicate, see
// internal/provenance) to path as a signed in-toto attestation via
// `cosign attest-blob`.
func AttestBlob(path string, opts AttestOptions) (string, error) {
	if err := RequireCosign(); err != nil {
		return "", err
	}

	out, err := exec.Command(cosignBinary, opts.args(path)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cosign attest-blob failed: %w\n%s", err, out)
	}
	return string(out), nil
}
