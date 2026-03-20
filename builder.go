package socwarden

import (
	"context"
	"time"
)

// EventBuilder provides a fluent API for constructing and sending events.
//
//	client.Event("auth.login.success").
//	    Actor("usr_123").
//	    ActorEmail("john@example.com").
//	    Meta("role", "admin").
//	    Send()
type EventBuilder struct {
	client *Client
	ctx    context.Context
	event  string
	opts   TrackOptions
}

// Context attaches a context.Context so the middleware-captured request
// data is included automatically.
func (b *EventBuilder) Context(ctx context.Context) *EventBuilder {
	b.ctx = ctx
	return b
}

// Actor sets the actor (user) ID.
func (b *EventBuilder) Actor(id string) *EventBuilder {
	b.opts.ActorID = id
	return b
}

// ActorEmail sets the actor email address.
func (b *EventBuilder) ActorEmail(email string) *EventBuilder {
	b.opts.ActorEmail = email
	return b
}

// IP sets the source IP address.
func (b *EventBuilder) IP(ip string) *EventBuilder {
	b.opts.IP = ip
	return b
}

// UserAgent sets the user-agent string.
func (b *EventBuilder) UserAgent(ua string) *EventBuilder {
	b.opts.UserAgent = ua
	return b
}

// Metadata merges the given map into the event metadata.
func (b *EventBuilder) Metadata(m map[string]any) *EventBuilder {
	if b.opts.Metadata == nil {
		b.opts.Metadata = make(map[string]any, len(m))
	}
	for k, v := range m {
		b.opts.Metadata[k] = v
	}
	return b
}

// Meta sets a single metadata key-value pair.
func (b *EventBuilder) Meta(key string, value any) *EventBuilder {
	if b.opts.Metadata == nil {
		b.opts.Metadata = make(map[string]any)
	}
	b.opts.Metadata[key] = value
	return b
}

// Timestamp sets the event timestamp.
func (b *EventBuilder) Timestamp(t time.Time) *EventBuilder {
	b.opts.Timestamp = t
	return b
}

// Severity sets the severity hint in metadata (used by the enricher).
func (b *EventBuilder) Severity(sev string) *EventBuilder {
	return b.Meta("_severity", sev)
}

// Resource attaches the resource that was acted upon.
func (b *EventBuilder) Resource(typ string, id string) *EventBuilder {
	b.opts.Resource = typ
	b.opts.ResourceID = id
	return b
}

// Send dispatches the event to the SOCWarden ingestor.
func (b *EventBuilder) Send() error {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.client.TrackWithContext(ctx, b.event, b.opts)
}
