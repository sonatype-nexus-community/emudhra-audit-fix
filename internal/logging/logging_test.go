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

package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseLevel tests parsing log level strings.
func TestParseLevel(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    slog.Level
		expectError bool
		errorMsg    string
	}{
		// Valid levels
		{"error lowercase", "error", slog.LevelError, false, ""},
		{"error uppercase", "ERROR", slog.LevelError, false, ""},
		{"error mixed case", "ErRoR", slog.LevelError, false, ""},
		{"warn", "warn", slog.LevelWarn, false, ""},
		{"warning", "warning", slog.LevelWarn, false, ""},
		{"WARN", "WARN", slog.LevelWarn, false, ""},
		{"WARNING", "WARNING", slog.LevelWarn, false, ""},
		{"info", "info", slog.LevelInfo, false, ""},
		{"INFO", "INFO", slog.LevelInfo, false, ""},
		{"trace", "trace", LevelTrace, false, ""},
		{"TRACE", "TRACE", LevelTrace, false, ""},
		{"Trace", "Trace", LevelTrace, false, ""},
		// Invalid levels
		{"invalid", "invalid", slog.Level(0), true, `invalid log level "invalid": must be one of error, warn, info, trace`},
		{"debug", "debug", slog.Level(0), true, `invalid log level "debug": must be one of error, warn, info, trace`},
		{"DEBUG", "DEBUG", slog.Level(0), true, `invalid log level "DEBUG": must be one of error, warn, info, trace`},
		{"empty", "", slog.Level(0), true, `invalid log level "": must be one of error, warn, info, trace`},
		{"numeric", "1", slog.Level(0), true, `invalid log level "1": must be one of error, warn, info, trace`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseLevel(tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, tt.errorMsg, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestLevelTrace tests that TRACE level is below DEBUG.
func TestLevelTrace(t *testing.T) {
	// TRACE should be 4 levels below DEBUG
	assert.Equal(t, slog.LevelDebug-4, LevelTrace)

	// TRACE should be the lowest level
	assert.Less(t, LevelTrace, slog.LevelDebug)
	assert.Less(t, LevelTrace, slog.LevelInfo)
	assert.Less(t, LevelTrace, slog.LevelWarn)
	assert.Less(t, LevelTrace, slog.LevelError)
}

// TestNewLogger tests logger creation with different levels and formats.
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		level  slog.Level
		format string
	}{
		{"error text", slog.LevelError, "text"},
		{"warn text", slog.LevelWarn, "text"},
		{"info text", slog.LevelInfo, "text"},
		{"trace text", LevelTrace, "text"},
		{"error json", slog.LevelError, "json"},
		{"warn json", slog.LevelWarn, "json"},
		{"info json", slog.LevelInfo, "json"},
		{"trace json", LevelTrace, "json"},
		{"empty format defaults to text", slog.LevelInfo, ""},
		{"TEXT uppercase", slog.LevelInfo, "TEXT"},
		{"JSON uppercase", slog.LevelInfo, "JSON"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(tt.level, tt.format, &buf)

			require.NotNil(t, logger)

			// Log a test message at the appropriate level for the test
			logger.Log(context.TODO(), tt.level, "test message")

			// Verify output was written (may be empty if level filters it out)
			output := buf.String()

			// Verify format when there is output
			if len(output) > 0 && strings.ToLower(tt.format) == "json" {
				assert.Contains(t, output, `"msg":"test message"`)
			} else if len(output) > 0 {
				assert.Contains(t, output, "test message")
			}
		})
	}
}

// TestLoggerLevels tests that logger respects level filtering.
func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		name         string
		loggerLevel  slog.Level
		messageLevel slog.Level
		expectOutput bool
	}{
		{"error logger shows error", slog.LevelError, slog.LevelError, true},
		{"error logger hides warn", slog.LevelError, slog.LevelWarn, false},
		{"error logger hides info", slog.LevelError, slog.LevelInfo, false},
		{"error logger hides trace", slog.LevelError, LevelTrace, false},
		{"warn logger shows error", slog.LevelWarn, slog.LevelError, true},
		{"warn logger shows warn", slog.LevelWarn, slog.LevelWarn, true},
		{"warn logger hides info", slog.LevelWarn, slog.LevelInfo, false},
		{"info logger shows error", slog.LevelInfo, slog.LevelError, true},
		{"info logger shows warn", slog.LevelInfo, slog.LevelWarn, true},
		{"info logger shows info", slog.LevelInfo, slog.LevelInfo, true},
		{"trace logger shows all", LevelTrace, slog.LevelError, true},
		{"trace logger shows trace", LevelTrace, LevelTrace, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(tt.loggerLevel, "text", &buf)

			// Log at the test level
			switch tt.messageLevel {
			case slog.LevelError:
				logger.Error("test")
			case slog.LevelWarn:
				logger.Warn("test")
			case slog.LevelInfo:
				logger.Info("test")
			case LevelTrace:
				logger.Log(context.TODO(), LevelTrace, "test")
			}

			if tt.expectOutput {
				assert.NotEmpty(t, buf.String())
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

// TestTraceLevelRendering tests that TRACE level is rendered as "TRACE" not "DEBUG-4".
func TestTraceLevelRendering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelTrace, "text", &buf)

	logger.Log(context.TODO(), LevelTrace, "trace message")

	output := buf.String()

	// Should contain "level=TRACE" not "level=DEBUG-4"
	assert.Contains(t, output, "level=TRACE")
	assert.NotContains(t, output, "DEBUG-4")
}

// TestTraceLevelRenderingJSON tests TRACE level rendering in JSON format.
func TestTraceLevelRenderingJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelTrace, "json", &buf)

	logger.Log(context.TODO(), LevelTrace, "trace message")

	output := buf.String()

	// Should contain "level":"TRACE" not "level":"DEBUG-4"
	assert.Contains(t, output, `"level":"TRACE"`)
	assert.NotContains(t, output, "DEBUG-4")
}

// TestNeverLogCredentials verifies the logging convention note.
// This is a documentation test - actual enforcement would require code review.
func TestNeverLogCredentialsConvention(t *testing.T) {
	// This test documents the convention from the package comment:
	// "Never log credentials: config.NXRMAuth, config.Webhook.Secret, or any
	// *config.Config field holding them, at any level including TRACE."

	// The convention is enforced through code review, not runtime checks.
	// This test exists to remind developers of the requirement.

	var buf bytes.Buffer
	logger := New(LevelTrace, "text", &buf)

	// Log a test message that does NOT contain credentials
	logger.Info("operation completed", "user", "alice", "action", "upload")

	// Verify the message was logged
	assert.Contains(t, buf.String(), "operation completed")
	assert.Contains(t, buf.String(), "alice")

	// NOTE: Never do this:
	// logger.Info("connected", "password", "secret123")  // WRONG!

	// Instead, filter out credentials before logging:
	// logger.Info("connected", "user", username)  // Correct
}

// TestReplaceLevelAttr tests the custom level attribute replacer.
func TestReplaceLevelAttr(t *testing.T) {
	tests := []struct {
		name     string
		attr     slog.Attr
		expected slog.Attr
	}{
		{
			name:     "TRACE level becomes TRACE string",
			attr:     slog.Any(slog.LevelKey, LevelTrace),
			expected: slog.String(slog.LevelKey, "TRACE"),
		},
		{
			name:     "ERROR level unchanged",
			attr:     slog.Any(slog.LevelKey, slog.LevelError),
			expected: slog.Any(slog.LevelKey, slog.LevelError),
		},
		{
			name:     "non-level key unchanged",
			attr:     slog.String("message", "test"),
			expected: slog.String("message", "test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceLevelAttr(nil, tt.attr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLoggerWithAttrs tests that logger can be used with additional attributes.
func TestLoggerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, "text", &buf)

	// Add attributes
	logger = logger.With("component", "test-component")
	logger.Info("message with attrs")

	output := buf.String()
	assert.Contains(t, output, "test-component")
	assert.Contains(t, output, "message with attrs")
}

// TestLoggerWithGroup tests that logger can be used with groups.
func TestLoggerWithGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, "json", &buf)

	// Add a group
	logger = logger.WithGroup("request")
	logger.Info("message in group", "id", "123")

	output := buf.String()
	// In JSON format, attributes should be nested under the group
	assert.Contains(t, output, "request")
}

// TestCaseInsensitiveFormat tests that format parameter is case-insensitive.
func TestCaseInsensitiveFormat(t *testing.T) {
	tests := []string{"json", "JSON", "Json", "jSoN"}

	for _, format := range tests {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(slog.LevelInfo, format, &buf)

			logger.Info("test")

			// All variations should produce JSON output
			assert.Contains(t, buf.String(), `"msg":"test"`)
		})
	}
}
