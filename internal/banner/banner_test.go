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

package banner

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPrintTTYGated tests that banner output is gated by TTY detection.
func TestPrintTTYGated(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		isTTY         bool
		expectOutput  bool
		expectVersion bool
	}{
		{
			name:          "TTY with version",
			version:       "1.0.0",
			isTTY:         true,
			expectOutput:  true,
			expectVersion: true,
		},
		{
			name:          "TTY with dev version",
			version:       "dev",
			isTTY:         true,
			expectOutput:  true,
			expectVersion: false,
		},
		{
			name:          "TTY with empty version",
			version:       "",
			isTTY:         true,
			expectOutput:  true,
			expectVersion: false,
		},
		{
			name:          "non-TTY with version",
			version:       "1.0.0",
			isTTY:         false,
			expectOutput:  false,
			expectVersion: false,
		},
		{
			name:          "non-TTY with dev version",
			version:       "dev",
			isTTY:         false,
			expectOutput:  false,
			expectVersion: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Override ttyChecker for testing
			originalChecker := ttyChecker
			ttyChecker = func() bool { return tt.isTTY }
			defer func() { ttyChecker = originalChecker }()

			Print(&buf, tt.version)

			if tt.expectOutput {
				// Banner should print something (we don't check exact content, just that it's non-empty)
				assert.NotEmpty(t, buf.String())
				if tt.expectVersion {
					assert.Contains(t, buf.String(), "Version:")
					assert.Contains(t, buf.String(), tt.version)
				} else {
					// Should not print version line for dev or empty
					if tt.version == "" || tt.version == "dev" {
						// Only banner, no version line
						assert.NotContains(t, buf.String(), "Version:")
					}
				}
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

// TestIsTTY tests the actual TTY detection (we can't easily test non-TTY in tests).
func TestIsTTY(t *testing.T) {
	// When running tests, stdout is typically not a TTY
	// This is a sanity check that the function doesn't panic
	result := isTTY()
	// We just verify it returns a boolean without error
	assert.IsType(t, true, result)
}

// TestBannerContent tests that the banner contains expected content.
func TestBannerContent(t *testing.T) {
	var buf bytes.Buffer

	// Force TTY mode
	originalChecker := ttyChecker
	ttyChecker = func() bool { return true }
	defer func() { ttyChecker = originalChecker }()

	Print(&buf, "1.2.3")

	output := buf.String()

	// Check that something was printed (banner is ASCII art, hard to match exactly)
	assert.NotEmpty(t, output)

	// Check version is printed
	assert.Contains(t, output, "1.2.3")

	assert.Contains(t, output, "███████╗ ██████╗ ███╗   ██╗", "the SONATYPE lettering")
	assert.Contains(t, output, "⬢⬡⬢⬡", "the hexagon rule")
	assert.Contains(t, output, "eMudhra CA compromise: developer tool audit and fixer")
	assert.Contains(t, output, "Running on: "+runtime.GOOS+"/"+runtime.GOARCH)
}

// TestBannerToPipe tests that banner is not printed to a pipe.
// This simulates: echo | emudhra-audit-fix (no banner)
func TestBannerToPipe(t *testing.T) {
	var buf bytes.Buffer

	// Simulate non-TTY (piped output)
	originalChecker := ttyChecker
	ttyChecker = func() bool { return false }
	defer func() { ttyChecker = originalChecker }()

	Print(&buf, "1.0.0")

	// No output when not a TTY
	assert.Empty(t, buf.String())
}

// TestBannerToFile tests that banner is not printed when redirected to a file.
// This simulates: emudhra-audit-fix > output.txt (no banner)
func TestBannerToFile(t *testing.T) {
	var buf bytes.Buffer

	// Simulate file redirect (non-TTY)
	originalChecker := ttyChecker
	ttyChecker = func() bool { return false }
	defer func() { ttyChecker = originalChecker }()

	Print(&buf, "1.0.0")

	// No output when redirecting to file
	assert.Empty(t, buf.String())
}

// TestBannerColorsDisabled tests that banner output works without color.
// The banner doesn't use colors currently, but this test verifies it works
// in a non-color environment.
func TestBannerColorsDisabled(t *testing.T) {
	var buf bytes.Buffer

	// Force TTY mode
	originalChecker := ttyChecker
	ttyChecker = func() bool { return true }
	defer func() { ttyChecker = originalChecker }()

	// Print should work regardless of color support
	Print(&buf, "1.0.0")

	assert.NotEmpty(t, buf.String())
	// Check that version was printed
	assert.Contains(t, buf.String(), "1.0.0")
}

// TestBannerVersionFormatting tests version formatting in the banner.
func TestBannerVersionFormatting(t *testing.T) {
	tests := []struct {
		name             string
		version          string
		expectedInOutput string
		notExpected      string
	}{
		{
			name:             "semantic version",
			version:          "1.2.3",
			expectedInOutput: "Version: 1.2.3",
		},
		{
			name:             "version with prerelease",
			version:          "2.0.0-beta.1",
			expectedInOutput: "Version: 2.0.0-beta.1",
		},
		{
			name:        "dev version",
			version:     "dev",
			notExpected: "Version:",
		},
		{
			name:        "empty version",
			version:     "",
			notExpected: "Version:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Force TTY mode
			originalChecker := ttyChecker
			ttyChecker = func() bool { return true }
			defer func() { ttyChecker = originalChecker }()

			Print(&buf, tt.version)

			if tt.expectedInOutput != "" {
				assert.Contains(t, buf.String(), tt.expectedInOutput)
			}
			if tt.notExpected != "" {
				assert.NotContains(t, buf.String(), tt.notExpected)
			}
		})
	}
}
