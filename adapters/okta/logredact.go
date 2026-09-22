// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Credential-redacting slog.Handler — the CHOKEPOINT for the BL-1 class.
//
// Rounds 4, 5 and 6 of review each found another member of the same class: a
// place where the SSWS token could reach a log line. Round 4 was the reflected
// 401 body, round 5 was the cap-straddling body and the Link header, round 6 was
// the JSON decode error and the scheme site. Every one of those fixes was correct
// and every one of them was a member-of-the-class patch, which is why the next
// round found another member.
//
// This file stops that. There are ~29 error-construction sites in this adapter
// and only a handful can be individually audited with confidence; rather than
// enumerate them, redaction is installed at the single place every diagnostic
// ultimately passes through — the slog.Handler. main.go builds ONE logger and
// hands it to the poller, the sink and the run loop, so wrapping that handler
// covers every current log path and every future one without anyone remembering
// to call a helper.
//
// What this does NOT replace: redactToken at the error-construction sites. A
// returned error can also reach a caller that formats it into a sink record or an
// HTTP response, neither of which passes through slog. The handler is the outer
// net for logs; the site-level calls remain the inner net for error strings.
//
// Fields swept: the record Message and every attribute VALUE (including values
// nested in groups and LogValuer results). Attribute KEYS are not swept — they are
// Go literals written by this package ("error", "event_uuid", "login"), never
// server-controlled data, and redacting them would make records unfilterable.

import (
	"context"
	"log/slog"
)

// redactingHandler wraps an slog.Handler and scrubs the adapter's own credential
// from every message and attribute value before the inner handler sees them.
type redactingHandler struct {
	inner  slog.Handler
	redact func(string) string
}

// newRedactingHandler wraps h so that every record it writes is passed through
// redact. If redact is nil the handler is returned unwrapped, because a nil
// scrubber would silently disable the only net covering log paths.
func newRedactingHandler(h slog.Handler, redact func(string) string) slog.Handler {
	if h == nil || redact == nil {
		return h
	}
	return &redactingHandler{inner: h, redact: redact}
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Scrub at bind time as well as at write time: an attribute bound with
	// WithAttrs is captured once and then emitted on every subsequent record, so
	// waiting until Handle would mean the same leak repeated per record.
	cleaned := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cleaned[i] = h.scrubAttr(a)
	}
	return &redactingHandler{inner: h.inner.WithAttrs(cleaned), redact: h.redact}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	// Group NAMES are Go literals in this package, not data.
	return &redactingHandler{inner: h.inner.WithGroup(name), redact: h.redact}
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = h.redact(r.Message)

	// The record is rebuilt rather than mutated: slog.Record exposes its
	// attributes only through the Attrs iterator, and its own docs say a Record
	// must not be modified after a copy has been handed out. NewRecord +
	// AddAttrs preserves Time, Level, Message and PC exactly.
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

// scrubAttr redacts an attribute's value. Keys are left alone: they are literals
// in this package and redacting them would destroy the trail's vocabulary.
func (h *redactingHandler) scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.redact(a.Value.String()))
	case slog.KindAny:
		// Errors and other opaque values are the interesting case: `logger.Error(
		// "poll cycle failed", "error", err)` carries whatever the wrapped chain
		// formatted, which is where the decode-error and transport-error leaks
		// surfaced. Formatting to a string and scrubbing loses the concrete type
		// for callers using errors.As on a LOG record — but nothing reads types
		// back out of a log line, and losing a credential is worse.
		if err, ok := a.Value.Any().(error); ok && err != nil {
			return slog.String(a.Key, h.redact(err.Error()))
		}
		return slog.String(a.Key, h.redact(a.Value.String()))
	case slog.KindGroup:
		attrs := a.Value.Group()
		cleaned := make([]slog.Attr, len(attrs))
		for i, g := range attrs {
			cleaned[i] = h.scrubAttr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(cleaned...)}
	default:
		// Numbers, bools, times and durations cannot carry a credential.
		return a
	}
}
