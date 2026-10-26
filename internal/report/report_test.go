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

package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
)

var update = flag.Bool("update", false, "update golden files")

func finding(tool, ver, path string, probe kinds.ProbeResult, evidence string, vc kinds.VersionCheck, vn string) kinds.Finding {
	f := kinds.NewFinding("test", tool)
	f.Path = path
	f.SetProbe(probe, evidence)
	f.SetVersion(ver, "", vc, vn)
	return f
}

// TestStatusDerivation is the script's report() status table: a conclusive
// probe wins; otherwise the version check decides LIKELY-*.
func TestStatusDerivation(t *testing.T) {
	tests := []struct {
		name  string
		probe kinds.ProbeResult
		vc    kinds.VersionCheck
		want  kinds.Status
		bad   bool
		ok    bool
	}{
		{"trusted beats a fixed version", kinds.ProbeTrusted, kinds.VersionOK, kinds.StatusAffected, true, false},
		{"trusted and behind", kinds.ProbeTrusted, kinds.VersionBehind, kinds.StatusAffected, true, false},
		{"rejected beats a behind version", kinds.ProbeRejected, kinds.VersionBehind, kinds.StatusOK, false, true},
		{"rejected and fixed", kinds.ProbeRejected, kinds.VersionOK, kinds.StatusOK, false, true},
		{"skipped and behind is likely affected", kinds.ProbeSkipped, kinds.VersionBehind, kinds.StatusLikelyAffected, true, false},
		{"skipped and no fix is likely affected", kinds.ProbeSkipped, kinds.VersionNoFix, kinds.StatusLikelyAffected, true, false},
		{"inconclusive and behind is likely affected", kinds.ProbeInconclusive, kinds.VersionBehind, kinds.StatusLikelyAffected, true, false},
		{"skipped and fixed is likely ok", kinds.ProbeSkipped, kinds.VersionOK, kinds.StatusLikelyOK, false, true},
		{"inconclusive and fixed is likely ok", kinds.ProbeInconclusive, kinds.VersionOK, kinds.StatusLikelyOK, false, true},
		{"skipped and n/a is unknown", kinds.ProbeSkipped, kinds.VersionNA, kinds.StatusUnknown, false, false},
		{"inconclusive and unreadable is unknown", kinds.ProbeInconclusive, kinds.VersionUnknown, kinds.StatusUnknown, false, false},
		{"empty probe and empty version is unknown", "", "", kinds.StatusUnknown, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := kinds.NewFinding("k", "t")
			f.ProbeResult = tt.probe
			f.VersionCheck = tt.vc
			assert.Equal(t, tt.want, f.Status())
			assert.Equal(t, tt.bad, f.Status().IsBad())
			assert.Equal(t, tt.ok, f.Status().IsOK())
		})
	}
}

func TestBehindButProtected(t *testing.T) {
	f := kinds.NewFinding("k", "t")
	f.ProbeResult, f.VersionCheck = kinds.ProbeRejected, kinds.VersionBehind
	assert.True(t, f.BehindButProtected())
	f.VersionCheck = kinds.VersionNoFix
	assert.True(t, f.BehindButProtected())
	f.VersionCheck = kinds.VersionOK
	assert.False(t, f.BehindButProtected())
	f.ProbeResult, f.VersionCheck = kinds.ProbeSkipped, kinds.VersionBehind
	assert.False(t, f.BehindButProtected(), "an unprobed old version is LIKELY-AFFECTED, not advisory")
}

// TestExitCode locks the safety property: any bad status exits 1, including
// version-only LIKELY-AFFECTED (a --no-network run on a vulnerable install).
func TestExitCode(t *testing.T) {
	affected := finding("node", "22.0.0", "/n", kinds.ProbeTrusted, "", kinds.VersionBehind, "fixed in 22.23.4")
	likely := finding("go", "1.26.4", "/g", kinds.ProbeSkipped, "--no-network", kinds.VersionBehind, "fixed in 1.26.10")
	ok := finding("curl", "8.7.1", "/c", kinds.ProbeRejected, "", kinds.VersionNA, "")
	likelyOK := finding("claude", "2.1.309", "/cl", kinds.ProbeSkipped, "--no-network", kinds.VersionOK, "fixed in 2.1.303")
	behindProtected := finding("uv", "0.13.0", "/u", kinds.ProbeRejected, "", kinds.VersionBehind, "fixed in 0.13.4")
	unknown := finding("py", "", "/p", kinds.ProbeInconclusive, "no network", kinds.VersionUnknown, "")

	tests := []struct {
		name     string
		findings []kinds.Finding
		want     int
	}{
		{"none", nil, 0},
		{"ok only", []kinds.Finding{ok, likelyOK}, 0},
		{"protected but behind", []kinds.Finding{behindProtected}, 0},
		{"unknown only", []kinds.Finding{unknown}, 0},
		{"affected", []kinds.Finding{affected}, 1},
		{"likely affected alone", []kinds.Finding{likely}, 1},
		{"likely affected among ok", []kinds.Finding{ok, likelyOK, likely}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExitCode(tt.findings))
		})
	}
}

func TestTally(t *testing.T) {
	fs := []kinds.Finding{
		finding("a", "1", "/a", kinds.ProbeTrusted, "", kinds.VersionNA, ""),
		finding("b", "1", "/b", kinds.ProbeSkipped, "x", kinds.VersionBehind, "n"),
		finding("c", "1", "/c", kinds.ProbeRejected, "", kinds.VersionNA, ""),
		finding("d", "1", "/d", kinds.ProbeSkipped, "x", kinds.VersionOK, "n"),
		finding("e", "", "/e", kinds.ProbeInconclusive, "x", kinds.VersionUnknown, ""),
	}
	assert.Equal(t, Counts{Bad: 2, OK: 2, Unknown: 1}, Tally(fs))
}

func TestDescribe(t *testing.T) {
	assert.Equal(t, "up to date", DescribeVersion(kinds.VersionOK))
	assert.Equal(t, "BEHIND", DescribeVersion(kinds.VersionBehind))
	assert.Equal(t, "NO FIX for this release line", DescribeVersion(kinds.VersionNoFix))
	assert.Equal(t, "n/a", DescribeVersion(kinds.VersionNA))
	assert.Equal(t, "could not determine", DescribeVersion(kinds.VersionUnknown))

	f := kinds.NewFinding("k", "t")
	f.SetProbe(kinds.ProbeTrusted, "")
	assert.Equal(t, "AFFECTED - connected to a host using the compromised chain", DescribeProbe(f))
	f.SetProbe(kinds.ProbeRejected, "")
	assert.Equal(t, "protected - certificate rejected", DescribeProbe(f))
	f.SetProbe(kinds.ProbeSkipped, "--no-network")
	assert.Equal(t, "skipped (--no-network)", DescribeProbe(f))
	f.SetProbe(kinds.ProbeInconclusive, "control host unreachable")
	assert.Equal(t, "inconclusive - control host unreachable", DescribeProbe(f))
}

func TestCompactWhy(t *testing.T) {
	tests := []struct {
		name string
		f    kinds.Finding
		want string
	}{
		{"affected", finding("t", "1", "/p", kinds.ProbeTrusted, "", kinds.VersionOK, "fixed in 2"), "trusts the compromised chain"},
		{"affected and behind", finding("t", "1", "/p", kinds.ProbeTrusted, "", kinds.VersionBehind, "fixed in 2"), "trusts the compromised chain; also behind (fixed in 2)"},
		{"ok", finding("t", "1", "/p", kinds.ProbeRejected, "", kinds.VersionOK, "fixed in 2"), "rejects the chain"},
		{"ok but behind", finding("t", "1", "/p", kinds.ProbeRejected, "", kinds.VersionBehind, "fixed in 2"), "rejects the chain, but older than the fixed release (fixed in 2)"},
		{"likely affected", finding("t", "1", "/p", kinds.ProbeSkipped, "--no-network", kinds.VersionBehind, "fixed in 2"), "version-only: fixed in 2"},
		{"likely ok", finding("t", "3", "/p", kinds.ProbeSkipped, "--no-network", kinds.VersionOK, "fixed in 2"), "version-only: fixed in 2"},
		{"page lists suffix trimmed", finding("t", "1", "/p", kinds.ProbeRejected, "", kinds.VersionBehind, "fixed in 2 (page lists more)"), "rejects the chain, but older than the fixed release (fixed in 2)"},
		{"unknown inconclusive", finding("t", "", "/p", kinds.ProbeInconclusive, "no usable CA bundle", kinds.VersionUnknown, ""), "no usable CA bundle"},
		{"unknown skipped", finding("t", "", "/p", kinds.ProbeSkipped, "--no-network", kinds.VersionNA, ""), "--no-network"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CompactWhy(tt.f))
		})
	}
	long := finding("t", "", "/p", kinds.ProbeInconclusive, string(bytes.Repeat([]byte("x"), 200)), kinds.VersionUnknown, "")
	assert.Len(t, CompactWhy(long), 90)
}

func mixed() []kinds.Finding {
	return []kinds.Finding{
		finding("node", "22.0.0", "/home/me/.nvm/versions/node/v22.0.0/bin/node", kinds.ProbeTrusted, "", kinds.VersionBehind, "fixed in 22.23.4"),
		finding("go", "1.26.4", "/usr/local/go/bin/go", kinds.ProbeSkipped, "--no-network", kinds.VersionBehind, "fixed in 1.26.10"),
		finding("curl", "8.7.1", "/usr/bin/curl", kinds.ProbeRejected, "", kinds.VersionNA, ""),
		finding("claude", "2.1.309", "/home/me/.local/bin/claude", kinds.ProbeSkipped, "--no-network", kinds.VersionOK, "fixed in 2.1.303"),
		finding("uv", "0.13.0", "/home/me/.local/bin/uv", kinds.ProbeRejected, "", kinds.VersionBehind, "fixed in 0.13.4"),
		finding("python", "", "/usr/bin/python3", kinds.ProbeInconclusive, "control host unreachable", kinds.VersionUnknown, ""),
	}
}

func golden(t *testing.T, name string, r *Reporter, fs []kinds.Finding) {
	t.Helper()
	var buf bytes.Buffer
	r.Output = &buf
	require.NoError(t, r.Report(fs))
	path := filepath.Join("testdata", name+".golden")
	if *update {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run: go test ./internal/report -update")
	assert.Equal(t, string(want), buf.String())
}

func TestGoldenCompact(t *testing.T) {
	golden(t, "compact-mixed", &Reporter{Home: "/home/me"}, mixed())
}

func TestGoldenCompactColor(t *testing.T) {
	golden(t, "compact-mixed-color", &Reporter{Home: "/home/me", Color: true}, mixed())
}

func TestGoldenCompactMissing(t *testing.T) {
	golden(t, "compact-missing", &Reporter{Missing: "deno bun pixi"}, nil)
}

func TestGoldenVerbose(t *testing.T) {
	golden(t, "verbose-mixed", &Reporter{Verbose: 1, Home: "/home/me"}, mixed())
}

func TestGoldenEmpty(t *testing.T) {
	golden(t, "compact-empty", &Reporter{}, nil)
}

func TestColorOffEmitsNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{Output: &buf}
	require.NoError(t, r.Report(mixed()))
	assert.NotContains(t, buf.String(), "\033[")
}
