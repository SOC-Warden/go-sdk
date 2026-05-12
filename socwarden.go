// Package socwarden provides a Go SDK for the SOCWarden security event
// tracking platform. It sends events to the SOCWarden ingestor via
// POST /v1/events and supports automatic request-context capture through
// standard net/http middleware.
package socwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sdkName    = "socwarden-go"
	sdkVersion = "1.0.0"

	defaultEndpoint = "https://ingest.socwarden.com"
	defaultTimeout  = 10 * time.Second

	backoffDuration = 1 * time.Hour
	probeInterval   = 5 * time.Minute
)

// D3 FIX: Event type validation regex — matches the ingestor's required format.
var eventTypeRegex = regexp.MustCompile(`^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$`)

// Client sends security events to the SOCWarden ingestor.
type Client struct {
	apiKey   string
	endpoint string
	timeout  time.Duration
	http     *http.Client

	// 429 back-off state (protected by mu).
	mu           sync.RWMutex
	backoffUntil time.Time
	lastProbe    time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithEndpoint overrides the default ingestor URL.
func WithEndpoint(url string) Option {
	return func(c *Client) { c.endpoint = url }
}

// WithTimeout sets the HTTP request timeout. Default is 10 s.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// New creates a Client with the given API key and options.
// It returns an error if the endpoint uses HTTP in production (SOCWARDEN_ENV=production).
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:   apiKey,
		endpoint: defaultEndpoint,
		timeout:  defaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	c.http = &http.Client{Timeout: c.timeout}

	// D2 FIX: Enforce HTTPS to prevent API key transmission in cleartext.
	if !strings.HasPrefix(c.endpoint, "https://") {
		if os.Getenv("SOCWARDEN_ENV") == "production" {
			panic("socwarden: endpoint must use HTTPS in production — API keys must not be transmitted in cleartext")
		}
		// Non-production: log a prominent warning via stderr.
		_, _ = fmt.Fprintln(os.Stderr, "[SOCWarden] WARNING: Endpoint is using HTTP. API keys will be transmitted in cleartext.")
	}

	return c
}

// Track sends a security event synchronously.
// Callers that need async behaviour should wrap the call in a goroutine.
// Returns an error if event type format is invalid.
func (c *Client) Track(event string, opts TrackOptions) error {
	// D3 FIX: Validate event type format before sending.
	if !eventTypeRegex.MatchString(event) {
		return fmt.Errorf("socwarden: invalid event type %q — must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$", event)
	}
	return c.TrackWithContext(context.Background(), event, opts)
}

// TrackWithContext is like Track but accepts an explicit context, which
// allows the middleware-captured request data to be included automatically.
func (c *Client) TrackWithContext(ctx context.Context, event string, opts TrackOptions) error {
	p := c.buildPayload(ctx, event)

	if opts.ActorID != "" {
		p.ActorID = opts.ActorID
	}
	if opts.ActorEmail != "" {
		p.ActorEmail = opts.ActorEmail
	}
	if opts.IP != "" {
		p.IP = sanitizeIP(opts.IP)
	}
	if opts.UserAgent != "" {
		p.UserAgent = opts.UserAgent
	}
	if opts.Metadata != nil {
		p.Metadata = opts.Metadata
	}
	if !opts.Timestamp.IsZero() {
		p.Timestamp = opts.Timestamp.Format(time.RFC3339)
	}
	if opts.Resource != "" {
		if p.Metadata == nil {
			p.Metadata = make(map[string]any)
		}
		p.Metadata["resource_type"] = opts.Resource
		if opts.ResourceID != "" {
			p.Metadata["resource_id"] = opts.ResourceID
		}
	}

	return c.send(p)
}

// TrackData sends an event with an arbitrary data map (mirrors the Laravel
// SDK's trackData method).
// Returns an error if event type format is invalid.
func (c *Client) TrackData(event string, data map[string]any) error {
	// D3 FIX: Validate event type format before sending.
	if !eventTypeRegex.MatchString(event) {
		return fmt.Errorf("socwarden: invalid event type %q — must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$", event)
	}
	return c.TrackDataWithContext(context.Background(), event, data)
}

// TrackDataWithContext is like TrackData but accepts a context for
// middleware-captured request data.
func (c *Client) TrackDataWithContext(ctx context.Context, event string, data map[string]any) error {
	p := c.buildPayload(ctx, event)

	if v, ok := data["actor_id"].(string); ok {
		p.ActorID = v
	}
	if v, ok := data["actor_email"].(string); ok {
		p.ActorEmail = v
	}
	if v, ok := data["ip"].(string); ok {
		p.IP = sanitizeIP(v)
	}
	if v, ok := data["user_agent"].(string); ok {
		p.UserAgent = v
	}
	if v, ok := data["metadata"].(map[string]any); ok {
		p.Metadata = v
	}
	if v, ok := data["timestamp"].(string); ok {
		p.Timestamp = v
	}

	return c.send(p)
}

// Event starts a fluent EventBuilder for the given event name.
func (c *Client) Event(name string) *EventBuilder {
	return &EventBuilder{client: c, event: name}
}

// -------------------------------------------------------------------------
//  Internal
// -------------------------------------------------------------------------

func (c *Client) buildPayload(ctx context.Context, event string) payload {
	p := payload{
		Event:  event,
		Source: "sdk",
	}

	// Attach auto-context from middleware if present.
	if rc := reqCtxFromContext(ctx); rc != nil {
		hostname, _ := os.Hostname()
		p.Context = &contextInfo{
			SDK:    sdkInfo{Name: sdkName, Version: sdkVersion},
			Server: serverInfo{Hostname: hostname, Runtime: "Go " + runtime.Version(), PID: os.Getpid()},
			Request: requestInfo{
				Method:         rc.Method,
				Path:           rc.Path,
				QueryString:    sanitizeQueryString(rc.QueryString),
				RemoteIP:       rc.RemoteIP,
				UserAgent:      rc.UserAgent,
				Referer:        rc.Referer,
				Origin:         rc.Origin,
				ContentType:    rc.ContentType,
				AcceptLanguage: rc.AcceptLanguage,
				RequestID:      rc.RequestID,
			},
			Browser: rc.Browser,
		}
	}

	return p
}

// sanitizeIP returns ip if it is a valid IPv4/IPv6 address, otherwise "".
// Matches the ingestor's validate:"omitempty,ip" constraint.
func sanitizeIP(ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func (c *Client) send(p payload) error {
	// Check back-off state.
	if c.inBackoff() {
		return fmt.Errorf("socwarden: rate limited, backing off")
	}

	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("socwarden: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("socwarden: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("socwarden: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := backoffDuration
		if v := resp.Header.Get("Retry-After"); v != "" {
			if secs, err := strconv.Atoi(v); err == nil {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
		c.enterBackoff(retryAfter)
		return fmt.Errorf("socwarden: rate limited (429), backing off for %s", retryAfter)
	}

	// Any successful response clears a previous back-off.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.clearBackoff()
		return nil
	}

	return fmt.Errorf("socwarden: unexpected status %d", resp.StatusCode)
}

// inBackoff returns true if the client should suppress requests. It allows
// a single probe every probeInterval so the client can auto-recover once
// the server lifts the rate limit.
func (c *Client) inBackoff() bool {
	c.mu.RLock()
	until := c.backoffUntil
	probe := c.lastProbe
	c.mu.RUnlock()

	now := time.Now()
	if now.Before(until) {
		// Still in back-off window — allow a probe every probeInterval.
		if now.Sub(probe) >= probeInterval {
			c.mu.Lock()
			c.lastProbe = now
			c.mu.Unlock()
			return false // allow this request as a probe
		}
		return true
	}
	return false
}

func (c *Client) enterBackoff(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoffUntil = time.Now().Add(d)
	c.lastProbe = time.Now()
}

func (c *Client) clearBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoffUntil = time.Time{}
	c.lastProbe = time.Time{}
}
