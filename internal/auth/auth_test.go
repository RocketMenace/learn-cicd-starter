package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}
	key, err := GetAPIKey(headers)
	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")
	key, err := GetAPIKey(headers)
	if key != "" {
		t.Errorf("expected empty key, got %q", key)
	}
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key-123")
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "my-secret-key-123" {
		t.Errorf("expected key %q, got %q", "my-secret-key-123", key)
	}
}
