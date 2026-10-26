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

// Package version provides version parsing and comparison.
// Port of the script's vcmp/ver_ge logic.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

// Version represents a parsed dotted-numeric version.
type Version struct {
	Parts []int
}

// Parse parses a version string into a Version struct.
// Non-numeric suffixes are stripped (e.g., "1.2.3-beta" -> [1, 2, 3]).
func Parse(s string) Version {
	// Strip non-numeric suffixes
	re := regexp.MustCompile(`^([0-9.]+)`)
	match := re.FindString(s)
	if match == "" {
		return Version{Parts: []int{0}}
	}

	// Remove trailing dots
	match = strings.TrimRight(match, ".")

	parts := strings.Split(match, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			result = append(result, n)
		} else {
			result = append(result, 0)
		}
	}

	if len(result) == 0 {
		return Version{Parts: []int{0}}
	}

	return Version{Parts: result}
}

// GE returns true if v >= other (greater than or equal).
// Missing parts are treated as 0.
func (v Version) GE(other Version) bool {
	maxLen := len(v.Parts)
	if len(other.Parts) > maxLen {
		maxLen = len(other.Parts)
	}

	for i := 0; i < maxLen; i++ {
		va := 0
		if i < len(v.Parts) {
			va = v.Parts[i]
		}
		vb := 0
		if i < len(other.Parts) {
			vb = other.Parts[i]
		}

		if va > vb {
			return true
		}
		if va < vb {
			return false
		}
	}

	return true // Equal
}

// Compare returns -1 if v < other, 0 if v == other, 1 if v > other.
func (v Version) Compare(other Version) int {
	maxLen := len(v.Parts)
	if len(other.Parts) > maxLen {
		maxLen = len(other.Parts)
	}

	for i := 0; i < maxLen; i++ {
		va := 0
		if i < len(v.Parts) {
			va = v.Parts[i]
		}
		vb := 0
		if i < len(other.Parts) {
			vb = other.Parts[i]
		}

		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}

	return 0 // Equal
}

// String returns the version as a dotted string.
func (v Version) String() string {
	parts := make([]string, len(v.Parts))
	for i, p := range v.Parts {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ".")
}
