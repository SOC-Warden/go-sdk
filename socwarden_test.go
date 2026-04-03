package socwarden

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrack_BuildsCorrectPayload(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		// Verify auth header
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-key")
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	err := c.Track("auth.login.success", TrackOptions{
		ActorID:    "usr_123",
		ActorEmail: "alice@example.com",
		IP:         "10.0.0.1",
		UserAgent:  "TestAgent/1.0",
		Metadata:   map[string]any{"role": "admin"},
	})
	if err != nil {
		t.Fatalf("Track: %v", err)
	}

	if received.Event != "auth.login.success" {
		t.Errorf("event = %q, want %q", received.Event, "auth.login.success")
	}
	if received.Source != "sdk" {
		t.Errorf("source = %q, want %q", received.Source, "sdk")
	}
	if received.ActorID != "usr_123" {
		t.Errorf("actor_id = %q, want %q", received.ActorID, "usr_123")
	}
	if received.ActorEmail != "alice@example.com" {
		t.Errorf("actor_email = %q, want %q", received.ActorEmail, "alice@example.com")
	}
	if received.IP != "10.0.0.1" {
		t.Errorf("ip = %q, want %q", received.IP, "10.0.0.1")
	}
	if received.UserAgent != "TestAgent/1.0" {
		t.Errorf("user_agent = %q, want %q", received.UserAgent, "TestAgent/1.0")
	}
	if received.Metadata["role"] != "admin" {
		t.Errorf("metadata[role] = %v, want %q", received.Metadata["role"], "admin")
	}
}

func TestTrackData_PassesRawMap(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	err := c.TrackData("server.ssh.login.failure", map[string]any{
		"actor_id":    "usr_456",
		"actor_email": "bob@example.com",
		"ip":          "192.168.1.1",
		"user_agent":  "OpenSSH/8.9",
		"metadata":    map[string]any{"attempts": float64(5)},
		"timestamp":   "2025-01-15T10:30:00Z",
	})
	if err != nil {
		t.Fatalf("TrackData: %v", err)
	}

	if received.Event != "server.ssh.login.failure" {
		t.Errorf("event = %q, want %q", received.Event, "server.ssh.login.failure")
	}
	if received.ActorID != "usr_456" {
		t.Errorf("actor_id = %q, want %q", received.ActorID, "usr_456")
	}
	if received.ActorEmail != "bob@example.com" {
		t.Errorf("actor_email = %q, want %q", received.ActorEmail, "bob@example.com")
	}
	if received.IP != "192.168.1.1" {
		t.Errorf("ip = %q, want %q", received.IP, "192.168.1.1")
	}
	if received.UserAgent != "OpenSSH/8.9" {
		t.Errorf("user_agent = %q, want %q", received.UserAgent, "OpenSSH/8.9")
	}
	if received.Timestamp != "2025-01-15T10:30:00Z" {
		t.Errorf("timestamp = %q, want %q", received.Timestamp, "2025-01-15T10:30:00Z")
	}
	if received.Metadata["attempts"] != float64(5) {
		t.Errorf("metadata[attempts] = %v, want %v", received.Metadata["attempts"], float64(5))
	}
}

func TestEventBuilder_FluentChain(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	err := c.Event("auth.mfa.enabled").
		Actor("usr_789").
		ActorEmail("carol@example.com").
		Meta("method", "totp").
		Meta("provider", "google").
		IP("172.16.0.10").
		UserAgent("Chrome/120").
		Severity("info").
		Resource("user", "usr_789").
		Send()
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if received.Event != "auth.mfa.enabled" {
		t.Errorf("event = %q, want %q", received.Event, "auth.mfa.enabled")
	}
	if received.ActorID != "usr_789" {
		t.Errorf("actor_id = %q, want %q", received.ActorID, "usr_789")
	}
	if received.ActorEmail != "carol@example.com" {
		t.Errorf("actor_email = %q, want %q", received.ActorEmail, "carol@example.com")
	}
	if received.IP != "172.16.0.10" {
		t.Errorf("ip = %q, want %q", received.IP, "172.16.0.10")
	}
	if received.UserAgent != "Chrome/120" {
		t.Errorf("user_agent = %q, want %q", received.UserAgent, "Chrome/120")
	}
	if received.Metadata["method"] != "totp" {
		t.Errorf("metadata[method] = %v, want %q", received.Metadata["method"], "totp")
	}
	if received.Metadata["provider"] != "google" {
		t.Errorf("metadata[provider] = %v, want %q", received.Metadata["provider"], "google")
	}
	if received.Metadata["_severity"] != "info" {
		t.Errorf("metadata[_severity] = %v, want %q", received.Metadata["_severity"], "info")
	}
	if received.Metadata["resource_type"] != "user" {
		t.Errorf("metadata[resource_type] = %v, want %q", received.Metadata["resource_type"], "user")
	}
	if received.Metadata["resource_id"] != "usr_789" {
		t.Errorf("metadata[resource_id] = %v, want %q", received.Metadata["resource_id"], "usr_789")
	}
}

func TestMiddleware_CapturesContext(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))

	// Create a handler that tracks an event using the middleware-enriched context.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := c.TrackWithContext(r.Context(), "api.request.received", TrackOptions{
			ActorID: "usr_mid",
		})
		if err != nil {
			t.Errorf("TrackWithContext: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(c)(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/dashboard?page=1", nil)
	req.RemoteAddr = "203.0.113.42:54321"
	req.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	req.Header.Set("Referer", "https://example.com/login")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Request-ID", "req-abc-123")

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want %d", rr.Code, http.StatusOK)
	}

	if received.Context == nil {
		t.Fatal("context is nil, expected middleware to populate it")
	}
	if received.Context.Request.Method != "POST" {
		t.Errorf("request.method = %q, want %q", received.Context.Request.Method, "POST")
	}
	if received.Context.Request.Path != "/api/dashboard" {
		t.Errorf("request.path = %q, want %q", received.Context.Request.Path, "/api/dashboard")
	}
	if received.Context.Request.QueryString != "page=1" {
		t.Errorf("request.query_string = %q, want %q", received.Context.Request.QueryString, "page=1")
	}
	if received.Context.Request.RemoteIP != "203.0.113.42" {
		t.Errorf("request.remote_ip = %q, want %q", received.Context.Request.RemoteIP, "203.0.113.42")
	}
	if received.Context.Request.UserAgent != "Mozilla/5.0 TestBrowser" {
		t.Errorf("request.user_agent = %q, want %q", received.Context.Request.UserAgent, "Mozilla/5.0 TestBrowser")
	}
	if received.Context.Request.Referer != "https://example.com/login" {
		t.Errorf("request.referer = %q, want %q", received.Context.Request.Referer, "https://example.com/login")
	}
	if received.Context.Request.Origin != "https://example.com" {
		t.Errorf("request.origin = %q, want %q", received.Context.Request.Origin, "https://example.com")
	}
	if received.Context.Request.ContentType != "application/json" {
		t.Errorf("request.content_type = %q, want %q", received.Context.Request.ContentType, "application/json")
	}
	if received.Context.Request.AcceptLanguage != "en-US,en;q=0.9" {
		t.Errorf("request.accept_language = %q, want %q", received.Context.Request.AcceptLanguage, "en-US,en;q=0.9")
	}
	if received.Context.Request.RequestID != "req-abc-123" {
		t.Errorf("request.request_id = %q, want %q", received.Context.Request.RequestID, "req-abc-123")
	}
	if received.Context.SDK.Name != sdkName {
		t.Errorf("sdk.name = %q, want %q", received.Context.SDK.Name, sdkName)
	}
	if received.Context.SDK.Version != sdkVersion {
		t.Errorf("sdk.version = %q, want %q", received.Context.SDK.Version, sdkVersion)
	}
}

func TestBackoff_On429(t *testing.T) {
	var callCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))

	// First call should go through and trigger backoff.
	err := c.Track("test.event.one", TrackOptions{})
	if err == nil {
		t.Fatal("expected error on 429, got nil")
	}

	// Second call should be skipped due to backoff (no HTTP request made).
	err = c.Track("test.event.two", TrackOptions{})
	if err == nil {
		t.Fatal("expected backoff error, got nil")
	}

	// Only 1 HTTP request should have been made (second was skipped).
	if got := callCount.Load(); got != 1 {
		t.Errorf("server received %d requests, want 1", got)
	}
}

func TestSanitizeQueryString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"redacts token", "token=abc123&name=test", "token=[REDACTED]&name=test"},
		{"redacts password", "user=admin&password=secret123", "user=admin&password=[REDACTED]"},
		{"redacts api_key", "api_key=xyz&page=2", "api_key=[REDACTED]&page=2"},
		{"redacts secret", "client_secret=foo&redirect=bar", "client_secret=[REDACTED]&redirect=bar"},
		{"redacts auth", "auth_code=abc&state=xyz", "auth_code=[REDACTED]&state=xyz"},
		{"redacts session", "session_id=s123&tab=home", "session_id=[REDACTED]&tab=home"},
		{"redacts csrf", "csrf_token=ct1&action=save", "csrf_token=[REDACTED]&action=save"},
		{"multiple sensitive", "token=a&key=b&name=ok", "token=[REDACTED]&key=[REDACTED]&name=ok"},
		{"empty string", "", ""},
		{"no sensitive params", "page=1&limit=20&sort=name", "page=1&limit=20&sort=name"},
		{"no value", "tokenonly&name=test", "tokenonly&name=test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeQueryString(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeQueryString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDefaultEndpoint(t *testing.T) {
	c := New("test-key")
	if c.endpoint != "https://ingest.socwarden.io" {
		t.Errorf("default endpoint = %q, want %q", c.endpoint, "https://ingest.socwarden.io")
	}
}

// TestBrowserContextHeaderIgnored verifies that the X-SOCWarden-Context header
// is NOT trusted or merged into event context (security fix D1 — header spoofing
// prevention). Attackers must not be able to poison server-side metadata by
// sending a crafted header value.
func TestBrowserContextHeaderIgnored(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))

	// Craft a spoofed context header an attacker might send to poison telemetry.
	spoofed := map[string]any{
		"hostname": "attacker-controlled-host",
		"pid":      float64(1),
		"ip":       "1.2.3.4",
	}
	spoofedJSON, _ := json.Marshal(spoofed)
	encoded := base64.StdEncoding.EncodeToString(spoofedJSON)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := c.TrackWithContext(r.Context(), "page.view", TrackOptions{})
		if err != nil {
			t.Errorf("TrackWithContext: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(c)(inner)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-SOCWarden-Context", encoded) // must be ignored

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	// The request must succeed.
	if rr.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200", rr.Code)
	}

	// The spoofed browser context must NOT appear in the event payload.
	if received.Context != nil && received.Context.Browser != nil {
		if received.Context.Browser["hostname"] == "attacker-controlled-host" {
			t.Error("X-SOCWarden-Context header was trusted — attacker can spoof server metadata")
		}
	}
}

func TestWithTimeout(t *testing.T) {
	c := New("test-key", WithTimeout(30*time.Second))
	if c.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want %v", c.timeout, 30*time.Second)
	}
}

func TestInvalidIP_IsStripped(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	_ = c.Track("auth.login.success", TrackOptions{IP: "not-an-ip"})

	if received.IP != "" {
		t.Errorf("expected IP to be stripped for invalid value, got %q", received.IP)
	}
}

func TestValidIP_IsKept(t *testing.T) {
	var received payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	c := New("test-key", WithEndpoint(ts.URL))
	_ = c.Track("auth.login.success", TrackOptions{IP: "192.168.1.1"})

	if received.IP != "192.168.1.1" {
		t.Errorf("expected IP %q to be kept, got %q", "192.168.1.1", received.IP)
	}
}
