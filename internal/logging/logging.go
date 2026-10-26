/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package logging builds this tool's *slog.Logger, with a fourth level
// (LevelTrace, below the stdlib's Debug) alongside the standard
// Warn/Info/Error. This tool does not use slog's Debug level at all: the
// four levels in play throughout this codebase are, from least to most
// severe:
//
//   - TRACE:   fine-grained step tracing (e.g. per-asset fetch, per-NXRM-call
//     entry/exit). Verbose; off by default.
//   - INFO:    pipeline step boundaries (resolved component, assembled
//     bundle, uploaded to S3, ...). The default level.
//   - WARNING: non-critical data conditions or graceful degradation (a
//     malformed timestamp falling back to now, a webhook ignored because its
//     repository isn't configured, an unrewritten VEX ref). The tool keeps
//     going; the operator should know something looked off.
//   - ERROR:   a failure that aborts the current operation (this publish,
//     this webhook delivery, this backfill component).
//
// Convention: log an ERROR exactly once, at the point that decides what to
// do about the failure -- a CLI skip-and-continue loop, or main's final
// exit. Inner packages return wrapped errors as before and do not log them;
// only their caller's handling point does. This avoids one root cause
// producing several duplicate ERROR lines as it propagates.
//
// Never log credentials: config.NXRMAuth, config.Webhook.Secret, or any
// *config.Config field holding them, at any level including TRACE.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// LevelTrace is a custom slog.Level below slog.LevelDebug. slog's Debug
// level is intentionally unused by this codebase; TRACE is the least severe
// level in play here.
const LevelTrace slog.Level = slog.LevelDebug - 4

// ParseLevel parses a case-insensitive level name ("error", "warn"/"warning",
// "info", "trace") into a slog.Level, or returns a descriptive error for any
// other input.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "error":
		return slog.LevelError, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	case "trace":
		return LevelTrace, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: must be one of error, warn, info, trace", s)
	}
}

// New builds a *slog.Logger writing to w at the given minimum level. format
// selects the handler: "json" for slog.JSONHandler, anything else
// (including "" and "text") for slog.TextHandler. The TRACE level is
// rendered as "TRACE" rather than slog's default "DEBUG-4".
func New(level slog.Level, format string, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceLevelAttr,
	}

	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}

func replaceLevelAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	if level, ok := a.Value.Any().(slog.Level); ok && level == LevelTrace {
		a.Value = slog.StringValue("TRACE")
	}
	return a
}
