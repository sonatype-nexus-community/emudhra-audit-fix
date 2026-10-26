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

package kinds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

func TestFindingRecordsFacts(t *testing.T) {
	f := NewFinding("node", "node")
	assert.Equal(t, StatusUnknown, f.Status(), "a new finding has no facts yet")

	f.SetProbe(ProbeTrusted, "connected to bad host")
	assert.Equal(t, ProbeTrusted, f.ProbeResult)
	assert.Equal(t, "connected to bad host", f.Evidence)
	assert.Equal(t, StatusAffected, f.Status())

	f2 := NewFinding("golang", "go")
	f2.SetVersion("1.26.0", "1.26.10", VersionBehind, "fixed in 1.26.10")
	assert.Equal(t, "1.26.0", f2.Version)
	assert.Equal(t, "1.26.10", f2.FixedVersion)
	assert.Equal(t, VersionBehind, f2.VersionCheck)
	assert.Equal(t, "fixed in 1.26.10", f2.VersionNote)
	assert.Equal(t, StatusLikelyAffected, f2.Status(), "skipped probe plus a behind version")

	f2.SetProbe(ProbeRejected, "")
	assert.Equal(t, StatusOK, f2.Status(), "a conclusive probe wins over the version")
	assert.True(t, f2.BehindButProtected())
}

func TestFindingGuidance(t *testing.T) {
	f := NewFinding("node", "node")
	f.AddGuidance("upgrade to 22.23.4",
		"Run: nvm install 22.23.4",
		"Then: nvm alias default 22.23.4")

	assert.Equal(t, "upgrade to 22.23.4", f.GuidanceCompact)
	require.Len(t, f.GuidanceFull, 2)
	assert.Equal(t, "Run: nvm install 22.23.4", f.GuidanceFull[0])
}

func TestFindingString(t *testing.T) {
	f := NewFinding("node", "node")
	f.Version = "22.23.0"
	f.ProbeResult = ProbeTrusted
	assert.Contains(t, f.String(), "node")
	assert.Contains(t, f.String(), "22.23.0")
	assert.Contains(t, f.String(), "AFFECTED")
}

func TestEnvGetenv(t *testing.T) {
	t.Setenv("EMUDHRA_TEST_VAR", "from-process")

	real := &Env{}
	assert.Equal(t, "from-process", real.Getenv("EMUDHRA_TEST_VAR"))

	fake := &Env{Environ: map[string]string{"PATH": "/a:/b", "HOME": "/h"}}
	assert.Equal(t, "", fake.Getenv("EMUDHRA_TEST_VAR"), "an injected environment hides the process one")
	assert.Equal(t, "/a:/b", fake.Path())
	assert.Equal(t, "/h", fake.Home())
}

func TestWantsSystemFix(t *testing.T) {
	mk := func(probe ProbeResult, vc VersionCheck, flag bool) Finding {
		f := NewFinding("k", "t")
		f.ProbeResult, f.VersionCheck, f.NeedsSystemGuidance = probe, vc, flag
		return f
	}
	tests := []struct {
		name string
		fs   []Finding
		want bool
	}{
		{"none", nil, false},
		{"affected and asks", []Finding{mk(ProbeTrusted, VersionNA, true)}, true},
		{"likely affected and asks (a --no-network run)", []Finding{mk(ProbeSkipped, VersionBehind, true)}, true},
		{"affected but its remedy is not the OS store", []Finding{mk(ProbeTrusted, VersionNA, false)}, false},
		{"asks but is protected", []Finding{mk(ProbeRejected, VersionNA, true)}, false},
		{"asks but only likely OK", []Finding{mk(ProbeSkipped, VersionOK, true)}, false},
		{"asks but unknown", []Finding{mk(ProbeInconclusive, VersionUnknown, true)}, false},
		{"one of several asks", []Finding{mk(ProbeRejected, VersionNA, false), mk(ProbeTrusted, VersionNA, true)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, WantsSystemFix(tt.fs))
		})
	}
}

// plan_add dedupes, and plan_uv_python keeps the newest target for a minor line.
func TestRequestsFor(t *testing.T) {
	req := func(kind, target, min string) Finding {
		f := NewFinding("python", "Python")
		f.Requests = []FixRequest{{Kind: kind, Target: target, Minimum: min}}
		return f
	}
	t.Run("none", func(t *testing.T) {
		assert.Empty(t, RequestsFor("uvpython", nil))
		assert.Empty(t, RequestsFor("uvpython", []Finding{NewFinding("k", "t")}))
	})
	t.Run("only requests addressed to the kind", func(t *testing.T) {
		got := RequestsFor("uvpython", []Finding{req("uvpython", "3.11", ""), req("uvtools", "ruff", ""), req("sys", "system", "")})
		assert.Equal(t, []FixRequest{{Kind: "uvpython", Target: "3.11"}}, got)
	})
	t.Run("a target asked for twice is one request", func(t *testing.T) {
		got := RequestsFor("uvtools", []Finding{req("uvtools", "ruff", ""), req("uvtools", "black", ""), req("uvtools", "ruff", "")})
		assert.Equal(t, []string{"ruff", "black"}, []string{got[0].Target, got[1].Target}, "first-seen order")
		assert.Len(t, got, 2)
	})
	t.Run("the highest minimum wins", func(t *testing.T) {
		got := RequestsFor("uvpython", []Finding{req("uvpython", "3.11", "3.11.15"), req("uvpython", "3.11", "3.11.17"), req("uvpython", "3.11", "3.11.16")})
		require.Len(t, got, 1)
		assert.Equal(t, "3.11.17", got[0].Minimum)
	})
	t.Run("a later request without a minimum does not erase one", func(t *testing.T) {
		got := RequestsFor("uvpython", []Finding{req("uvpython", "3.11", "3.11.17"), req("uvpython", "3.11", "")})
		assert.Equal(t, "3.11.17", got[0].Minimum)
	})
	t.Run("an empty minimum is filled by a later one", func(t *testing.T) {
		got := RequestsFor("uvpython", []Finding{req("uvpython", "3.11", ""), req("uvpython", "3.11", "3.11.17")})
		assert.Equal(t, "3.11.17", got[0].Minimum)
	})
	t.Run("separate minors stay separate", func(t *testing.T) {
		got := RequestsFor("uvpython", []Finding{req("uvpython", "3.11", "3.11.17"), req("uvpython", "3.12", "3.12.12")})
		require.Len(t, got, 2)
		assert.Equal(t, "3.12.12", got[1].Minimum)
	})
	t.Run("a request with no target is ignored", func(t *testing.T) {
		assert.Empty(t, RequestsFor("uvpython", []Finding{req("uvpython", "", "3.11.17")}))
	})
}

func TestResultOfMapsEveryVerdict(t *testing.T) {
	for v, want := range map[probe.Verdict]ProbeResult{
		probe.VerdictTrusted: ProbeTrusted, probe.VerdictRejected: ProbeRejected,
		probe.VerdictSkipped: ProbeSkipped, probe.VerdictInconclusive: ProbeInconclusive, "": ProbeInconclusive,
	} {
		assert.Equal(t, want, ResultOf(v), "%q", v)
	}
}
