package client

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestJWTExpiryReadsExpiryClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	if got := jwtExpiry(fmt.Sprintf("header.%s.signature", payload)); got != 4102444800 {
		t.Fatalf("jwtExpiry() = %d, want 4102444800", got)
	}
}

func TestJWTExpiryIgnoresMalformedTokens(t *testing.T) {
	for _, token := range []string{"", "not-a-jwt", "a.%%%b.c", "a.e30.c"} {
		if got := jwtExpiry(token); got != 0 {
			t.Fatalf("jwtExpiry(%q) = %d, want 0", token, got)
		}
	}
}

func TestOpenAIResponseTextPrefersOutputText(t *testing.T) {
	resp := openAIResponse{OutputText: "top-level", Output: []openAIOutputMessage{{Type: "message"}}}
	if got := openAIResponseText(resp); got != "top-level" {
		t.Fatalf("openAIResponseText() = %q, want %q", got, "top-level")
	}
}

func TestEffectiveOpenAIModelMapsCodexOAuthAlias(t *testing.T) {
	auth := openAIAuth{OAuth: true, Model: "gpt-5.6-luna"}
	if got := effectiveOpenAIModel(auth, "gpt-5-codex"); got != "gpt-5.6-luna" {
		t.Fatalf("effectiveOpenAIModel() = %q, want %q", got, "gpt-5.6-luna")
	}
	if got := effectiveOpenAIModel(auth, "gpt-5.6-luna"); got != "gpt-5.6-luna" {
		t.Fatalf("explicit OAuth model was changed to %q", got)
	}
}

func TestResolveOpenAIAuthUsesExplicitAPIKey(t *testing.T) {
	auth, err := resolveOpenAIAuth("sk-test")
	if err != nil {
		t.Fatalf("resolveOpenAIAuth() error = %v", err)
	}
	if auth.OAuth || auth.Endpoint != openAIResponsesURL || auth.Token != "sk-test" {
		t.Fatalf("explicit API key resolved incorrectly: %+v", auth)
	}
}

func TestLoadCodexModelsFiltersHiddenEntries(t *testing.T) {
	models, _ := loadCodexModels()
	if len(models) == 0 {
		t.Fatal("loadCodexModels() returned no models")
	}
	for _, model := range models {
		if model.Slug == "gpt-reserve" || model.Slug == "codex-auto-review" {
			t.Fatalf("hidden model %q leaked into visible model list", model.Slug)
		}
	}
}
