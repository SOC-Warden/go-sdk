package socwarden

import "time"

// TrackOptions holds the parameters for a Track call.
type TrackOptions struct {
	ActorID    string
	ActorEmail string
	IP         string
	UserAgent  string
	Metadata   map[string]any
	Timestamp  time.Time
	Resource   string
	ResourceID string
}

// payload is the JSON body sent to POST /v1/events.
type payload struct {
	Event      string         `json:"event"`
	Source     string         `json:"source"`
	ActorID    string         `json:"actor_id,omitempty"`
	ActorEmail string         `json:"actor_email,omitempty"`
	IP         string         `json:"ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Timestamp  string         `json:"timestamp,omitempty"`
	Context    *contextInfo   `json:"context,omitempty"`
}

// contextInfo holds automatic context captured by the middleware.
type contextInfo struct {
	SDK     sdkInfo        `json:"sdk"`
	Server  serverInfo     `json:"server"`
	Request requestInfo    `json:"request"`
	Browser browserContext `json:"browser,omitempty"`
}

type sdkInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type serverInfo struct {
	Hostname string `json:"hostname"`
	Runtime  string `json:"runtime"`
	PID      int    `json:"pid"`
}

type requestInfo struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	QueryString    string `json:"query_string,omitempty"`
	RemoteIP       string `json:"ip,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	Referer        string `json:"referer,omitempty"`
	Origin         string `json:"origin,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
}

// contextInfo may optionally carry browser context relayed from the browser SDK.
type browserContext map[string]any

// requestContext is the per-request data captured by Middleware and stored
// in the request's context.Context.
type requestContext struct {
	Method         string
	Path           string
	QueryString    string
	RemoteIP       string
	UserAgent      string
	Referer        string
	Origin         string
	ContentType    string
	AcceptLanguage string
	RequestID      string
	Browser        browserContext
}
