package socwarden

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// contextKey is an unexported type to prevent collisions in context values.
type contextKey struct{}

// reqCtxKey is the context key for per-request data captured by Middleware.
var reqCtxKey = contextKey{}

// sensitiveParams is the set of query parameter name substrings that should
// be redacted by sanitizeQueryString.
var sensitiveParams = []string{
	"token", "key", "password", "secret", "code", "auth", "session", "csrf",
}

// Middleware returns standard net/http middleware that captures the current
// request's method, path, remote address, user-agent, query string, referer,
// origin, content-type, accept-language, request ID, and browser context
// into the request's context.Context. Subsequent Track calls made with that
// context (via TrackWithContext, TrackDataWithContext, or EventBuilder.Context)
// automatically include this data.
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api/action", handler)
//	http.ListenAndServe(":8080", socwarden.Middleware(client)(mux))
func Middleware(client *Client) func(http.Handler) http.Handler {
	_ = client // reserved for future per-client middleware config
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := &requestContext{
				Method:         r.Method,
				Path:           r.URL.Path,
				QueryString:    r.URL.RawQuery,
				UserAgent:      r.UserAgent(),
				Referer:        r.Header.Get("Referer"),
				Origin:         r.Header.Get("Origin"),
				ContentType:    r.Header.Get("Content-Type"),
				AcceptLanguage: r.Header.Get("Accept-Language"),
			}

			// Extract the IP without port.
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				rc.RemoteIP = host
			} else {
				rc.RemoteIP = r.RemoteAddr
			}

			// Check common request-ID headers.
			if id := r.Header.Get("X-Request-ID"); id != "" {
				rc.RequestID = id
			} else if id := r.Header.Get("X-Correlation-ID"); id != "" {
				rc.RequestID = id
			}

			// D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
			// allows any client to spoof server-side metadata. Browser context from
			// incoming request headers is no longer merged into server-side context.

			ctx := context.WithValue(r.Context(), reqCtxKey, rc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sanitizeQueryString redacts values of sensitive query parameters. A parameter
// is considered sensitive if its lowercase name contains any of the strings in
// sensitiveParams (e.g. "token", "password", "secret", etc.).
func sanitizeQueryString(qs string) string {
	if qs == "" {
		return ""
	}

	pairs := strings.Split(qs, "&")
	for i, pair := range pairs {
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			continue
		}
		paramName := strings.ToLower(pair[:eqIdx])
		for _, s := range sensitiveParams {
			if strings.Contains(paramName, s) {
				pairs[i] = pair[:eqIdx+1] + "[REDACTED]"
				break
			}
		}
	}
	return strings.Join(pairs, "&")
}

// reqCtxFromContext extracts the per-request context set by Middleware.
func reqCtxFromContext(ctx context.Context) *requestContext {
	if rc, ok := ctx.Value(reqCtxKey).(*requestContext); ok {
		return rc
	}
	return nil
}
