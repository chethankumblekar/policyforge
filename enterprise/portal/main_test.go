package main

import (
	"os"
	"testing"
)

func TestEnvOr_ReturnsEnvValueWhenSet(t *testing.T) {
	t.Setenv("POLICYFORGE_PORTAL_TEST_VAR", "from-env")
	if got := envOr("POLICYFORGE_PORTAL_TEST_VAR", "fallback"); got != "from-env" {
		t.Errorf("expected \"from-env\", got %q", got)
	}
}

func TestEnvOr_ReturnsFallbackWhenUnset(t *testing.T) {
	os.Unsetenv("POLICYFORGE_PORTAL_TEST_VAR_UNSET")
	if got := envOr("POLICYFORGE_PORTAL_TEST_VAR_UNSET", "fallback"); got != "fallback" {
		t.Errorf("expected \"fallback\", got %q", got)
	}
}
