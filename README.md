# socwarden-go

Official Go SDK for [SOCWarden](https://socwarden.com) -- send security events to the SOCWarden ingestor with zero external dependencies.

## Install

```bash
go get github.com/SOC-Warden/socwarden-go
```

## Quick Start

```go
package main

import (
    "log"

    socwarden "github.com/SOC-Warden/socwarden-go"
)

func main() {
    client := socwarden.New("your-api-key")

    // Simple tracking
    err := client.Track("auth.login.success", socwarden.TrackOptions{
        ActorID:    "usr_123",
        ActorEmail: "john@example.com",
        IP:         "203.0.113.42",
    })
    if err != nil {
        log.Printf("socwarden: %v", err)
    }
}
```

## Fluent Builder

```go
err := client.Event("data.exported").
    Actor("usr_123").
    ActorEmail("john@example.com").
    Resource("Report", "rpt_456").
    Meta("format", "csv").
    Severity("medium").
    Send()
```

## Raw Data Map

```go
err := client.TrackData("auth.login.failure", map[string]any{
    "actor_email": "unknown@example.com",
    "ip":          "198.51.100.7",
    "metadata": map[string]any{
        "reason": "invalid_password",
    },
})
```

## net/http Middleware

The middleware captures request context (method, path, remote IP, user-agent, request ID) and attaches it to the request's `context.Context`. Use the `WithContext` variants or pass the context through the builder to include this data automatically.

```go
package main

import (
    "net/http"

    socwarden "github.com/SOC-Warden/socwarden-go"
)

func main() {
    client := socwarden.New("your-api-key")

    mux := http.NewServeMux()
    mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
        // Context from middleware is included automatically
        err := client.Event("data.exported").
            Context(r.Context()).
            Actor("usr_123").
            Meta("format", "csv").
            Send()
        if err != nil {
            http.Error(w, "failed", http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    })

    handler := socwarden.Middleware(client)(mux)
    http.ListenAndServe(":8080", handler)
}
```

## Async Usage

Go convention is synchronous calls. Wrap in a goroutine if you need fire-and-forget:

```go
go func() {
    if err := client.Track("auth.login.success", opts); err != nil {
        log.Printf("socwarden: %v", err)
    }
}()
```

## Configuration

```go
client := socwarden.New("your-api-key",
    socwarden.WithEndpoint("https://custom-ingestor.example.com"),
    socwarden.WithTimeout(5 * time.Second),
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `WithEndpoint(url)` | `https://ingestor.socwarden.com` | Ingestor base URL |
| `WithTimeout(d)` | `10s` | HTTP request timeout |

## Rate Limit Handling

The SDK automatically handles HTTP 429 responses:

1. On a 429, the client enters a 1-hour back-off (or uses the `Retry-After` header value).
2. During back-off, a single probe request is allowed every 5 minutes.
3. If the probe succeeds, back-off is cleared and normal operation resumes.

## API Contract

All events are sent as `POST /v1/events` with a Bearer token. The ingestor returns 202 immediately; enrichment happens asynchronously.

```json
{
  "event": "auth.login.success",
  "source": "sdk",
  "actor_id": "usr_123",
  "actor_email": "john@example.com",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "metadata": {
    "role": "admin",
    "resource_type": "Report",
    "resource_id": "rpt_456"
  },
  "timestamp": "2025-01-15T10:30:00Z",
  "context": {
    "sdk": { "name": "socwarden-go", "version": "1.0.0" },
    "server": { "hostname": "app-1", "runtime": "Go go1.22", "pid": 12345 },
    "request": { "method": "POST", "path": "/api/export", "remote_ip": "203.0.113.42" }
  }
}
```

## License

See the repository root for license information.
