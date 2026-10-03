package cloud

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestConfigRequiresStrongSessionSecret(t *testing.T) {
	t.Setenv("AGENTSHIELD_SESSION_SECRET", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("missing secret accepted")
	}
	t.Setenv("AGENTSHIELD_SESSION_SECRET", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("short secret accepted")
	}
	t.Setenv("AGENTSHIELD_SESSION_SECRET", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}
