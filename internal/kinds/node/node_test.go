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

package node

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// TestNodeLineCheck tests the NodeLineCheck helper function.
// This verifies the fix version lookup per major line.
func TestNodeLineCheck(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantCheck kinds.VersionCheck
		wantFixed string
	}{
		{
			name:      "22.x behind",
			version:   "22.16.0",
			wantCheck: kinds.VersionBehind,
			wantFixed: "22.23.4",
		},
		{
			name:      "22.x fixed",
			version:   "22.23.4",
			wantCheck: kinds.VersionOK,
			wantFixed: "22.23.4",
		},
		{
			name:      "22.x newer",
			version:   "22.99.0",
			wantCheck: kinds.VersionOK,
			wantFixed: "22.23.4",
		},
		{
			name:      "24.x behind",
			version:   "24.16.0",
			wantCheck: kinds.VersionBehind,
			wantFixed: "24.22.1",
		},
		{
			name:      "24.x fixed",
			version:   "24.22.1",
			wantCheck: kinds.VersionOK,
			wantFixed: "24.22.1",
		},
		{
			name:      "26.x behind",
			version:   "26.1.0",
			wantCheck: kinds.VersionBehind,
			wantFixed: "26.12.1",
		},
		{
			name:      "26.x fixed",
			version:   "26.12.1",
			wantCheck: kinds.VersionOK,
			wantFixed: "26.12.1",
		},
		{
			name:      "27.x newer than fixed lines",
			version:   "27.0.0",
			wantCheck: kinds.VersionOK,
			wantFixed: "",
		},
		{
			name:      "28.x newer than fixed lines",
			version:   "28.0.0",
			wantCheck: kinds.VersionOK,
			wantFixed: "",
		},
		{
			name:      "25.x no fix - between fixed lines",
			version:   "25.1.0",
			wantCheck: kinds.VersionNoFix,
			wantFixed: "22.23.4, 24.22.1 or 26.12.1",
		},
		{
			name:      "23.x no fix - between fixed lines",
			version:   "23.0.0",
			wantCheck: kinds.VersionNoFix,
			wantFixed: "22.23.4, 24.22.1 or 26.12.1",
		},
		{
			name:      "21.x no fix - older than first fixed line",
			version:   "21.0.0",
			wantCheck: kinds.VersionNoFix,
			wantFixed: "22.23.4, 24.22.1 or 26.12.1",
		},
		{
			name:      "empty version",
			version:   "",
			wantCheck: kinds.VersionUnknown,
			wantFixed: "",
		},
		{
			name:      "with v prefix - 22.x behind",
			version:   "v22.16.0",
			wantCheck: kinds.VersionBehind,
			wantFixed: "22.23.4",
		},
		{
			name:      "with v prefix - 24.x behind",
			version:   "v24.16.0",
			wantCheck: kinds.VersionBehind,
			wantFixed: "24.22.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check, fixed, note := NodeLineCheck(tt.version)
			assert.Equal(t, tt.wantCheck, check, "VersionCheck mismatch")
			assert.Equal(t, tt.wantFixed, fixed, "Fixed version mismatch")
			// Note should contain useful information
			if tt.wantCheck != kinds.VersionUnknown {
				assert.NotEmpty(t, note, "Note should not be empty for known checks")
			}
		})
	}
}

// TestNodeKindBasics tests basic Kind functionality.
func TestNodeKindBasics(t *testing.T) {
	k := New()

	assert.Equal(t, "node", k.ID())
	assert.Equal(t, "Node.js installations", k.Describe())

	// Applicable on all platforms
	app := k.Applicable(testutil.NewDarwinHost())
	assert.True(t, app.Applies)

	app = k.Applicable(testutil.NewLinuxHost())
	assert.True(t, app.Applies)
}

// TestNodeAuditEmpty tests audit with no node installations.
func TestNodeAuditEmpty(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	env.Environ = map[string]string{
		"HOME": t.TempDir(),
		"PATH": "", // Empty PATH - no node found
	}

	k := New()
	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "No findings when no node is installed")
}

// TestNodeAuditWithFakeRunner tests audit with a fake runner.
func TestNodeAuditWithFakeRunner(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	home := t.TempDir()
	env.Environ = map[string]string{
		"HOME":              home,
		"PATH":              "", // Empty PATH - will use EMUDHRA_NODE_BINS
		"EMUDHRA_NODE_BINS": "", // Not set - just test with empty
	}
	env.Offline = true // Skip network probes

	k := New()
	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	// Empty findings since no node found
	assert.Empty(t, findings)
}

// TestJudgeProbeOutput tests the probe output judging logic.
func TestJudgeProbeOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantResult kinds.ProbeResult
	}{
		{
			name: "all rejected - protected",
			output: `ok https://github.com/
certerr https://dv-g3b-emudhra.we-have-a-problem.com/
certerr https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`,
			wantResult: kinds.ProbeRejected,
		},
		{
			name: "one trusted - affected",
			output: `ok https://github.com/
ok https://dv-g3b-emudhra.we-have-a-problem.com/
certerr https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`,
			wantResult: kinds.ProbeTrusted,
		},
		{
			name: "control failed - inconclusive",
			output: `err https://github.com/
certerr https://dv-g3b-emudhra.we-have-a-problem.com/`,
			wantResult: kinds.ProbeInconclusive,
		},
		{
			name:       "empty output - inconclusive",
			output:     ``,
			wantResult: kinds.ProbeInconclusive,
		},
		{
			name: "both trusted - affected",
			output: `ok https://github.com/
ok https://dv-g3b-emudhra.we-have-a-problem.com/
ok https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`,
			wantResult: kinds.ProbeTrusted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := kinds.ResultOf(probe.JudgeOutput(tt.output))
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

// TestWhereFrom tests the version manager detection.
func TestWhereFrom(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	home := t.TempDir()
	env.Environ = map[string]string{
		"HOME":    home,
		"NVM_DIR": home + "/.nvm",
	}

	k := &Kind{}

	tests := []struct {
		path     string
		expected string
	}{
		{home + "/.nvm/versions/node/v24.16.0/bin/node", "nvm"},
		{home + "/.volta/tools/image/node/24.16.0/bin/node", "volta"},
		{home + "/.local/share/fnm/node-versions/24.16.0/installation/bin/node", "fnm"},
		{home + "/.asdf/installs/nodejs/24.16.0/bin/node", "asdf"},
		{home + "/.local/share/mise/installs/node/24.16.0/bin/node", "mise"},
		{"/opt/homebrew/opt/node@24/bin/node", "brew"},
		{"/usr/local/opt/node/bin/node", "brew"},
		{"/usr/local/bin/node", "system"},
		{"/usr/bin/node", "system"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := k.whereFrom(context.Background(), env, tt.path)
			assert.Equal(t, tt.expected, result, "Path: %s", tt.path)
		})
	}
}

// TestUpgradeHint tests the upgrade hint generation.
func TestUpgradeHint(t *testing.T) {
	tests := []struct {
		how  string
		fixv string
		want string
	}{
		{"nvm", "24.22.1", "nvm install 24.22.1"},
		{"volta", "24.22.1", "volta install node@24.22.1"},
		{"fnm", "24.22.1", "fnm install 24.22.1"},
		{"mise", "24.22.1", "mise use -g node@24.22.1"},
		{"asdf", "24.22.1", "asdf install nodejs 24.22.1"},
		{"brew", "24.22.1", "brew upgrade node"},
		{"system", "24.22.1", "https://nodejs.org"},
		{"unknown", "24.22.1", "https://nodejs.org"},
	}

	for _, tt := range tests {
		t.Run(tt.how, func(t *testing.T) {
			hint := upgradeHint(tt.how, tt.fixv)
			assert.Equal(t, tt.want, hint)
		})
	}
}

// TestDescribeProbeResult tests the probe result description.
func TestDescribeProbeResult(t *testing.T) {
	assert.Contains(t, describeProbeResult(kinds.ProbeTrusted), "trusted")
	assert.Contains(t, describeProbeResult(kinds.ProbeRejected), "rejected")
	assert.Contains(t, describeProbeResult(kinds.ProbeInconclusive), "inconclusive")
	assert.Contains(t, describeProbeResult(kinds.ProbeSkipped), "skipped")
}

// TestNodeKindImplementsInterfaces verifies the Kind implements required interfaces.
func TestNodeKindImplementsInterfaces(t *testing.T) {
	// Kind interface
	_ = kinds.Kind(New())
}

// TestFakeRunnerDetection tests that the fake runner is correctly set up.
func TestFakeRunnerDetection(t *testing.T) {
	env := testutil.NewTestEnvT(t)
	fr := env.Run.(*exec.FakeRunner)
	require.NotNil(t, fr, "FakeRunner should be set up")
}

// Node is shown as it prints itself ("v24.22.1"), while the line checks work on the bare number.
func TestNodeVersionIsShownAsNodePrintsIt(t *testing.T) {
	fake := exec.NewFakeRunner()
	fake.AddSuccess("/x/node --version", "v24.22.1\n")
	env := testutil.NewTestEnvT(t)
	env.Run = fake

	got := (&Kind{}).getNodeVersion(context.Background(), env, "/x/node")

	assert.Equal(t, "v24.22.1", got)
	check, fixed, _ := NodeLineCheck(got)
	assert.Equal(t, kinds.VersionOK, check)
	assert.Equal(t, "24.22.1", fixed)
}
