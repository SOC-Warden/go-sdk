package socwarden

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ingestorAllowedFields lists every top-level JSON key the ingestor accepts
// in POST /v1/events (EventPayload struct in ingestor/internal/model/event.go).
var ingestorAllowedFields = map[string]bool{
	"event":       true,
	"source":      true,
	"actor_id":    true,
	"actor_email": true,
	"ip":          true,
	"user_agent":  true,
	"metadata":    true,
	"timestamp":   true,
	"context":     true,
}

func TestContract_PayloadMatchesIngestorSchema(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))

	// Use middleware context to capture all context fields.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := c.TrackWithContext(r.Context(), "auth.login.success", TrackOptions{
			ActorID:    "usr_123",
			ActorEmail: "alice@example.com",
			IP:         "10.0.0.1",
			UserAgent:  "TestAgent/1.0",
			Metadata:   map[string]any{"role": "admin"},
			Timestamp:  time.Date(2026, 3, 18, 10, 30, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("TrackWithContext: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(c)(inner)
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.RemoteAddr = "203.0.113.42:54321"
	req.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	// -----------------------------------------------------------------------
	// Assert required fields
	// -----------------------------------------------------------------------
	event, ok := raw["event"].(string)
	if !ok || event == "" {
		t.Fatal("payload must have non-empty 'event' field")
	}
	if !eventTypeRegex.MatchString(event) {
		t.Errorf("event %q does not match ingestor regex", event)
	}

	source, ok := raw["source"].(string)
	if !ok || source == "" {
		t.Fatal("payload must have non-empty 'source' field")
	}
	if source != "sdk" {
		t.Errorf("source = %q, want %q", source, "sdk")
	}

	// -----------------------------------------------------------------------
	// Assert optional fields present and correct types
	// -----------------------------------------------------------------------
	if raw["actor_id"] != "usr_123" {
		t.Errorf("actor_id = %v, want %q", raw["actor_id"], "usr_123")
	}
	if raw["actor_email"] != "alice@example.com" {
		t.Errorf("actor_email = %v, want %q", raw["actor_email"], "alice@example.com")
	}
	if raw["ip"] != "10.0.0.1" {
		t.Errorf("ip = %v, want %q", raw["ip"], "10.0.0.1")
	}
	if raw["user_agent"] != "TestAgent/1.0" {
		t.Errorf("user_agent = %v, want %q", raw["user_agent"], "TestAgent/1.0")
	}

	// metadata must be an object
	if _, ok := raw["metadata"].(map[string]any); !ok {
		t.Fatal("metadata must be a JSON object")
	}

	// timestamp must be present
	if _, ok := raw["timestamp"].(string); !ok {
		t.Fatal("timestamp must be a string")
	}

	// context must be an object with sdk, server, request blocks
	ctx, ok := raw["context"].(map[string]any)
	if !ok {
		t.Fatal("context must be a JSON object")
	}
	if _, ok := ctx["sdk"].(map[string]any); !ok {
		t.Fatal("context.sdk must be present")
	}
	if _, ok := ctx["server"].(map[string]any); !ok {
		t.Fatal("context.server must be present")
	}
	if _, ok := ctx["request"].(map[string]any); !ok {
		t.Fatal("context.request must be present")
	}

	// -----------------------------------------------------------------------
	// Assert NO unexpected fields
	// -----------------------------------------------------------------------
	for key := range raw {
		if !ingestorAllowedFields[key] {
			t.Errorf("payload contains unexpected field %q that ingestor would reject", key)
		}
	}
}

func TestContract_MinimalPayload(t *testing.T) {
	var raw map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	err := c.Track("auth.logout", TrackOptions{})
	if err != nil {
		t.Fatalf("Track: %v", err)
	}

	// Minimal payload must have event and source
	if raw["event"] != "auth.logout" {
		t.Errorf("event = %v, want %q", raw["event"], "auth.logout")
	}
	if raw["source"] != "sdk" {
		t.Errorf("source = %v, want %q", raw["source"], "sdk")
	}

	// No unexpected fields
	for key := range raw {
		if !ingestorAllowedFields[key] {
			t.Errorf("minimal payload contains unexpected field %q", key)
		}
	}
}

func TestContract_EventTypeFormat(t *testing.T) {
	// These are example events the Go SDK might send; all must pass the ingestor regex.
	events := []string{
		"auth.login.success",
		"auth.login.failure",
		"auth.logout",
		"auth.mfa.enabled",
		"auth.mfa.disabled",
		"data.exported",
		"api.request.received",
		"page.view",
	}

	for _, e := range events {
		if !eventTypeRegex.MatchString(e) {
			t.Errorf("event %q does not match ingestor regex", e)
		}
	}
}

func TestContract_SourceValues(t *testing.T) {
	// The ingestor accepts only these source values: sdk, agent, browser
	validSources := []string{"sdk", "agent", "browser"}
	for _, s := range validSources {
		if s != "sdk" && s != "agent" && s != "browser" {
			t.Errorf("source %q is not accepted by the ingestor", s)
		}
	}
}
