package signer

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSignOptions_Args(t *testing.T) {
	cases := []struct {
		name string
		opts SignOptions
		want []string
	}{
		{
			name: "key and bundle",
			opts: SignOptions{Key: "cosign.key", Bundle: "out.bundle.json"},
			want: []string{"sign-blob", "--yes", "--key", "cosign.key", "--bundle", "out.bundle.json", "blob.txt"},
		},
		{
			name: "keyless, no bundle",
			opts: SignOptions{},
			want: []string{"sign-blob", "--yes", "blob.txt"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.opts.args("blob.txt")
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected args %v, got %v", tc.want, got)
			}
		})
	}
}

func TestAttestOptions_Args(t *testing.T) {
	opts := AttestOptions{
		Key:               "cosign.key",
		PredicatePath:     "predicate.json",
		PredicateType:     "slsaprovenance",
		Bundle:            "out.bundle.json",
		OutputAttestation: "out.att.json",
	}

	want := []string{
		"attest-blob", "--yes", "--predicate", "predicate.json",
		"--type", "slsaprovenance",
		"--key", "cosign.key",
		"--bundle", "out.bundle.json",
		"--output-attestation", "out.att.json",
		"blob.txt",
	}

	got := opts.args("blob.txt")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expected args %v, got %v", want, got)
	}
}

func TestAttestOptions_ArgsMinimal(t *testing.T) {
	opts := AttestOptions{PredicatePath: "predicate.json"}
	want := []string{"attest-blob", "--yes", "--predicate", "predicate.json", "blob.txt"}

	got := opts.args("blob.txt")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expected args %v, got %v", want, got)
	}
}

func TestRequireCosign_MissingBinary(t *testing.T) {
	old := cosignBinary
	cosignBinary = "policyforge-cosign-does-not-exist"
	defer func() { cosignBinary = old }()

	err := RequireCosign()
	if err == nil {
		t.Fatal("expected an error when cosign isn't on PATH, got nil")
	}
	if !strings.Contains(err.Error(), "install") {
		t.Errorf("expected error to include install guidance, got: %v", err)
	}
}

func TestRequireCosign_PresentBinary(t *testing.T) {
	skipIfCosignMissing(t)
	if err := RequireCosign(); err != nil {
		t.Errorf("expected no error with cosign on PATH, got: %v", err)
	}
}

func TestSignBlob_MissingCosignErrors(t *testing.T) {
	old := cosignBinary
	cosignBinary = "policyforge-cosign-does-not-exist"
	defer func() { cosignBinary = old }()

	if _, err := SignBlob("blob.txt", SignOptions{}); err == nil {
		t.Fatal("expected an error when cosign isn't on PATH, got nil")
	}
}

func TestAttestBlob_MissingCosignErrors(t *testing.T) {
	old := cosignBinary
	cosignBinary = "policyforge-cosign-does-not-exist"
	defer func() { cosignBinary = old }()

	if _, err := AttestBlob("blob.txt", AttestOptions{PredicatePath: "predicate.json"}); err == nil {
		t.Fatal("expected an error when cosign isn't on PATH, got nil")
	}
}

// TestSignBlob_LocalKeyLiveIntegration exercises the real cosign binary
// end to end: generates a throwaway local key pair (fully offline), then
// signs a blob with it. cosign's --bundle output records a Rekor
// transparency log entry even for local-key signing, so this needs
// network access to rekor.sigstore.dev — it's skipped (not failed) in
// sandboxes where that's unreachable (e.g. behind a TLS-intercepting
// proxy), since that's an environment limitation, not a defect in this
// wrapper.
func TestSignBlob_LocalKeyLiveIntegration(t *testing.T) {
	skipIfCosignMissing(t)
	t.Setenv("COSIGN_PASSWORD", "")

	dir := t.TempDir()
	keyPrefix := filepath.Join(dir, "cosign")
	generateKeyPair(t, keyPrefix)

	blobPath := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(blobPath, []byte("policyforge test artifact"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	bundlePath := filepath.Join(dir, "blob.bundle.json")
	_, err := SignBlob(blobPath, SignOptions{Key: keyPrefix + ".key", Bundle: bundlePath})
	if err != nil {
		skipIfRekorUnreachable(t, err)
		t.Fatalf("SignBlob returned error: %v", err)
	}

	if info, statErr := os.Stat(bundlePath); statErr != nil || info.Size() == 0 {
		t.Fatalf("expected a non-empty bundle file at %s", bundlePath)
	}
}

func TestAttestBlob_LocalKeyLiveIntegration(t *testing.T) {
	skipIfCosignMissing(t)
	t.Setenv("COSIGN_PASSWORD", "")

	dir := t.TempDir()
	keyPrefix := filepath.Join(dir, "cosign")
	generateKeyPair(t, keyPrefix)

	blobPath := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(blobPath, []byte("policyforge test artifact"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	predicatePath := filepath.Join(dir, "predicate.json")
	if err := os.WriteFile(predicatePath, []byte(`{"builder":{"id":"test"}}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	bundlePath := filepath.Join(dir, "blob.att.bundle.json")
	_, err := AttestBlob(blobPath, AttestOptions{
		Key:           keyPrefix + ".key",
		PredicatePath: predicatePath,
		PredicateType: "slsaprovenance",
		Bundle:        bundlePath,
	})
	if err != nil {
		skipIfRekorUnreachable(t, err)
		t.Fatalf("AttestBlob returned error: %v", err)
	}

	if info, statErr := os.Stat(bundlePath); statErr != nil || info.Size() == 0 {
		t.Fatalf("expected a non-empty attestation bundle file at %s", bundlePath)
	}
}

func skipIfCosignMissing(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed on PATH; skipping live integration test")
	}
}

func skipIfRekorUnreachable(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, "rekor") || strings.Contains(msg, "transparency log") {
		t.Skipf("skipping: cosign's bundle format needs network access to Rekor, which isn't reachable in this environment: %v", err)
	}
}

func generateKeyPair(t *testing.T, prefix string) {
	t.Helper()
	cmd := exec.Command("cosign", "generate-key-pair", "--output-key-prefix", prefix)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair failed: %v\n%s", err, out)
	}
}
