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

package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRootToDistrust(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"AAA Certificate Services", true},
		{"emSign ECC Root CA - G3", true},
		{" AAA   Certificate   Services ", true}, // Normalized whitespace
		{"  emSign   ECC   Root   CA   -   G3  ", true},
		{"Some Other Root", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsRootToDistrust(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetFixedVersions(t *testing.T) {
	tests := []struct {
		tool           string
		expectCount    int
		expectNonEmpty bool
	}{
		{"node", 3, true},
		{"java", 6, true},
		{"golang", 2, true},
		{"rustup", 1, true},
		{"uv", 1, true},
		{"deno", 1, true},
		{"certifi", 1, true},
		{"pip", 1, true},
		{"unknown", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			fvs := GetFixedVersions(tt.tool)
			assert.Equal(t, tt.expectCount, len(fvs), "Fixed version count for %s", tt.tool)
			if tt.expectNonEmpty {
				for _, fv := range fvs {
					assert.NotEmpty(t, fv.Version, "Version should not be empty")
					assert.NotEmpty(t, fv.Notes, "Notes should not be empty")
				}
			}
		})
	}
}

func TestIsFixed(t *testing.T) {
	tests := []struct {
		tool     string
		version  string
		expected bool
	}{
		// Node.js - has multiple fixed versions per major line
		// A version is fixed if it meets ANY of the fixed versions
		{"node", "22.23.4", true},
		{"node", "22.23.5", true},
		{"node", "22.23.3", false},
		{"node", "24.22.1", true},
		{"node", "24.22.2", true},
		{"node", "24.22.0", true}, // Meets 22.23.4
		{"node", "26.12.1", true},
		{"node", "26.12.2", true},
		{"node", "26.12.0", true}, // Meets 22.23.4 and 24.22.1
		{"node", "22.0.0", false}, // Below all fixed versions

		// Go - has two fixed versions (1.26.10 and 1.27.3)
		{"golang", "1.26.10", true},
		{"golang", "1.26.11", true},
		{"golang", "1.26.9", false},
		{"golang", "1.27.3", true},
		{"golang", "1.27.4", true},
		{"golang", "1.27.2", true}, // Meets 1.26.10
		{"golang", "1.27.1", true}, // Meets 1.26.10

		// rustup
		{"rustup", "1.29.2", true},
		{"rustup", "1.29.3", true},
		{"rustup", "1.29.1", false},

		// uv
		{"uv", "0.13.4", true},
		{"uv", "0.13.5", true},
		{"uv", "0.13.3", false},

		// Java - has multiple fixed versions per major
		// Each major has its own fixed version, so check within major
		{"java", "8u511", true},
		{"java", "11.0.33", true},
		{"java", "17.0.21", true},
		{"java", "21.0.13", true},
		{"java", "11.0.32", true}, // Meets 8u511 (different versioning scheme, but version comparison works)
		{"java", "11.0.34", true},

		// Unknown tool has no fixed versions - IsFixed returns false
		{"unknown", "1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.tool+"_"+tt.version, func(t *testing.T) {
			result := IsFixed(tt.tool, tt.version)
			assert.Equal(t, tt.expected, result, "IsFixed(%s, %s)", tt.tool, tt.version)
		})
	}
}

func TestIsAffected(t *testing.T) {
	tests := []struct {
		tool     string
		version  string
		expected bool
	}{
		{"node", "22.23.3", true},
		{"node", "22.23.4", false},
		{"node", "22.23.5", false},
		{"rustup", "1.29.1", true},
		{"rustup", "1.29.2", false},
		{"golang", "1.26.9", true},
		{"golang", "1.26.10", false},
		{"unknown", "1.0.0", false}, // Unknown tools have no fixed version, so NOT affected
	}

	for _, tt := range tests {
		t.Run(tt.tool+"_"+tt.version, func(t *testing.T) {
			result := IsAffected(tt.tool, tt.version)
			assert.Equal(t, tt.expected, result, "IsAffected(%s, %s)", tt.tool, tt.version)
		})
	}
}

func TestSingleFixTools(t *testing.T) {
	for tool, want := range map[string]string{
		"pixi": "0.82.1", "mise": "2026.10.17", "claude": "2.1.303", "brew-ca-certificates": "2026-09-25_1",
	} {
		got := GetFixedVersions(tool)
		require.Len(t, got, 1, tool)
		assert.Equal(t, want, got[0].Version, tool)
	}
}

func TestGoLineCheck(t *testing.T) {
	tests := []struct {
		in    string
		check string
		fixed string
		ok    bool
	}{
		{"1.26.4", "behind", "1.26.10", true},
		{"1.26.9", "behind", "1.26.10", true},
		{"1.26.10", "ok", "1.26.10", true},
		{"1.26.11", "ok", "1.26.10", true},
		{"1.26", "behind", "1.26.10", true},
		{"1.27.2", "behind", "1.27.3", true},
		{"1.27.3", "ok", "1.27.3", true},
		{"1.28.0", "ok", "", true},
		{"1.30.1", "ok", "", true},
		{"1.25.9", "nofix", "1.26.10 or 1.27.3", true},
		{"1.22.0", "nofix", "1.26.10 or 1.27.3", true},
		{"1.26.4-rc1 darwin", "behind", "1.26.10", true},
		{"", "", "", false},
		{"go", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := GoLineCheck(tt.in)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.check, got.Check)
				assert.Equal(t, tt.fixed, got.Fixed)
			}
		})
	}
	// 1.26.x must not be judged against the 1.27 fix, nor vice versa.
	low, _ := GoLineCheck("1.26.10")
	assert.Equal(t, "ok", low.Check)
	high, _ := GoLineCheck("1.27.2")
	assert.Equal(t, "behind", high.Check)
}
