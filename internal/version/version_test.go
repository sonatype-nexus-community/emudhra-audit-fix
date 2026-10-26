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

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"22.23.4", []int{22, 23, 4}},
		{"24.22.1", []int{24, 22, 1}},
		{"26.12.1", []int{26, 12, 1}},
		{"1.29.2", []int{1, 29, 2}},
		{"0.13.4", []int{0, 13, 4}},
		{"2026.10.19", []int{2026, 10, 19}},
		{"1.2.3-beta", []int{1, 2, 3}},
		{"1.2", []int{1, 2}},
		{"1", []int{1}},
		{"", []int{0}},
		{"invalid", []int{0}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := Parse(tt.input)
			assert.Equal(t, tt.expected, v.Parts, "Parse(%q)", tt.input)
		})
	}
}

func TestGE(t *testing.T) {
	tests := []struct {
		a, b   string
		result bool
	}{
		// Equal versions
		{"1.2.3", "1.2.3", true},
		{"1.2", "1.2.0", true}, // Missing parts = 0
		{"1.2.0", "1.2", true},

		// Greater than
		{"1.2.4", "1.2.3", true},
		{"1.3.0", "1.2.9", true},
		{"2.0.0", "1.9.9", true},
		{"22.23.4", "22.23.3", true},

		// Less than
		{"1.2.2", "1.2.3", false},
		{"1.1.9", "1.2.0", false},
		{"1.9.9", "2.0.0", false},
		{"22.23.3", "22.23.4", false},

		// Fixed version examples from the advisory
		{"22.23.4", "22.23.3", true}, // Node.js fixed >= 22.23.4
		{"24.22.1", "24.22.0", true}, // Node.js fixed >= 24.22.1
		{"26.12.1", "26.12.0", true}, // Node.js fixed >= 26.12.1
		{"1.29.2", "1.29.1", true},   // rustup fixed >= 1.29.2
		{"0.13.4", "0.13.3", true},   // uv fixed >= 0.13.4
		{"1.26.10", "1.26.9", true},  // Go fixed >= 1.26.10
		{"1.27.3", "1.27.2", true},   // Go fixed >= 1.27.3
	}

	for _, tt := range tests {
		t.Run(tt.a+" >= "+tt.b, func(t *testing.T) {
			va := Parse(tt.a)
			vb := Parse(tt.b)
			result := va.GE(vb)
			assert.Equal(t, tt.result, result, "Parse(%q).GE(Parse(%q))", tt.a, tt.b)
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b   string
		result int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.4", "1.2.3", 1},
		{"1.2.2", "1.2.3", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.9.9", "2.0.0", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_cmp_"+tt.b, func(t *testing.T) {
			va := Parse(tt.a)
			vb := Parse(tt.b)
			result := va.Compare(vb)
			assert.Equal(t, tt.result, result, "Parse(%q).Compare(Parse(%q))", tt.a, tt.b)
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		parts  []int
		result string
	}{
		{[]int{1, 2, 3}, "1.2.3"},
		{[]int{22, 23, 4}, "22.23.4"},
		{[]int{1}, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			v := Version{Parts: tt.parts}
			assert.Equal(t, tt.result, v.String())
		})
	}
}
