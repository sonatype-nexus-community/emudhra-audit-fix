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

package versiononly

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// testSpec creates a simple ToolSpec for testing
func testSpec() ToolSpec {
	return ToolSpec{
		ID:           "testtool",
		Name:         "Test Tool",
		Binary:       "testtool",
		AdvisoryTool: "pixi", // Use pixi's advisory entry for tests
		ExtraCandidates: func(home string) []string {
			return []string{home + "/.testtool/bin/testtool"}
		},
		Guidance: func(fv string) (string, []string) {
			return "testtool upgrade", []string{"Upgrade to " + fv}
		},
	}
}

func TestKind_ID(t *testing.T) {
	k := New(testSpec())
	assert.Equal(t, "testtool", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New(testSpec())
	assert.Equal(t, "Test Tool", k.Describe())
}

func TestKind_Applicable(t *testing.T) {
	tests := []struct {
		name string
		host platform.Host
	}{
		{"darwin", testutil.NewDarwinHost()},
		{"linux", testutil.NewLinuxHost()},
		{"linux alpine", platform.Host{OS: "linux", Family: platform.FamilyAlpine}},
		{"linux redhat", platform.Host{OS: "linux", Family: platform.FamilyRedHat}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New(testSpec())
			got := k.Applicable(tt.host)
			assert.True(t, got.Applies)
			assert.Empty(t, got.Reason)
		})
	}
}

func TestKind_Audit_NotInstalled(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": "",
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "no findings when tool is not installed")
}

func TestKind_Audit_Behind(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create a fake binary
	binDir := filepath.Join(tempHome, ".testtool", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	binPath := filepath.Join(binDir, "testtool")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\necho 'testtool 0.1.0'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": binDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "testtool 0.1.0\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for behind version")

	f := findings[0]
	assert.Equal(t, "testtool", f.Kind)
	assert.Equal(t, "Test Tool", f.Tool)
	assert.Equal(t, "0.1.0", f.Version)
	assert.Equal(t, "0.82.1", f.FixedVersion) // pixi's fixed version
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Equal(t, kinds.VersionBehind, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
	assert.Equal(t, kinds.VersionOnlyProbeReason, f.Evidence)
	assert.Contains(t, f.GuidanceCompact, "testtool upgrade")
	assert.NotEmpty(t, f.GuidanceFull)
}

func TestKind_Audit_Fixed(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	binDir := filepath.Join(tempHome, ".testtool", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	binPath := filepath.Join(binDir, "testtool")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\necho 'testtool 0.82.1'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": binDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "testtool 0.82.1\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for fixed version")

	f := findings[0]
	assert.Equal(t, "testtool", f.Kind)
	assert.Equal(t, "Test Tool", f.Tool)
	assert.Equal(t, "0.82.1", f.Version)
	assert.Equal(t, "0.82.1", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
	assert.Equal(t, kinds.VersionOK, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
}

func TestKind_Audit_VerionNewerThanFixed(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	binDir := filepath.Join(tempHome, ".testtool", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	binPath := filepath.Join(binDir, "testtool")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\necho 'testtool 1.0.0'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": binDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "testtool 1.0.0\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "1.0.0", f.Version)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
	assert.Equal(t, kinds.VersionOK, f.VersionCheck)
}

func TestKind_Audit_VersionUnreadable(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	binDir := filepath.Join(tempHome, ".testtool", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	binPath := filepath.Join(binDir, "testtool")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": binDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{ExitCode: 1, Error: nil}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
	assert.Contains(t, f.Evidence, "version check failed")
	assert.Equal(t, kinds.StatusUnknown, f.Status())
}

func TestKind_Audit_MultiplePaths_SameBinary(t *testing.T) {
	k := New(testSpec())

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create a real binary
	binDir := filepath.Join(tempHome, ".testtool", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	realBin := filepath.Join(binDir, "testtool")
	require.NoError(t, os.WriteFile(realBin, []byte("#!/bin/sh\necho 'testtool 0.82.1'\n"), 0o755))

	// Create a symlink to the same binary (simulates PATH + extra candidate)
	linkDir := filepath.Join(tempHome, "bin")
	require.NoError(t, os.MkdirAll(linkDir, 0o755))
	linkBin := filepath.Join(linkDir, "testtool")
	require.NoError(t, os.Symlink(realBin, linkBin))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": linkDir + ":" + binDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "testtool 0.82.1\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Should only find ONE binary, not two, because symlinks resolve to the same binary
	assert.Len(t, findings, 1, "deduplicated by resolved path")
}

func TestKind_Audit_MultipleBinaries_DifferentVersions(t *testing.T) {
	spec := ToolSpec{
		ID:           "testtool",
		Name:         "Test Tool",
		Binary:       "testtool",
		AdvisoryTool: "pixi",
		ExtraCandidates: func(home string) []string {
			return []string{
				home + "/.testtool/v1/bin/testtool",
				home + "/.testtool/v2/bin/testtool",
			}
		},
		Guidance: func(fv string) (string, []string) {
			return "upgrade", []string{"Upgrade to " + fv}
		},
	}
	k := New(spec)

	tempHome, err := os.MkdirTemp("", "testtool-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create two different binaries
	for i, version := range []string{"0.1.0", "0.82.1"} {
		binDir := filepath.Join(tempHome, ".testtool", "v"+string(rune('1'+i)), "bin")
		require.NoError(t, os.MkdirAll(binDir, 0o755))

		binPath := filepath.Join(binDir, "testtool")
		require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\necho 'testtool "+version+"'\n"), 0o755))
	}

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": "",
	}

	runner := exec.NewFakeRunner()
	callCount := 0
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		callCount++
		// First call for v1, second for v2
		version := "0.1.0"
		if callCount == 2 {
			version = "0.82.1"
		}
		return exec.CommandResult{Stdout: "testtool " + version + "\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Should find TWO binaries, one behind, one fixed
	require.Len(t, findings, 2)
	assert.Equal(t, kinds.StatusLikelyAffected, findings[0].Status())
	assert.Equal(t, kinds.StatusLikelyOK, findings[1].Status())
}

func TestExtractFirstField(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple version",
			input:    "2.1.303\n",
			expected: "2.1.303",
		},
		{
			name:     "version with extra info",
			input:    "2026.10.17 linux-arm64 (2024-10-23)\n",
			expected: "2026.10.17",
		},
		{
			name:     "multiline output",
			input:    "2026.10.17\nextra info\n",
			expected: "2026.10.17",
		},
		{
			name:     "empty output",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \n",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFirstField(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestKind_Audit_Hermetic(t *testing.T) {
	// Verify that tests are hermetic: no HOST PATH or HOME leakage
	k := New(testSpec())

	// Create a temp home with NO binaries
	tempHome, err := os.MkdirTemp("", "hermetic-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	// Empty environment = hermetic test
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": "",
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "hermetic test with no binaries should find nothing")
}

func TestKind_Audit_WithGARBAGEPath(t *testing.T) {
	// Test with PATH set to garbage to verify it doesn't crash
	k := New(testSpec())

	env := testutil.NewTestEnv()
	env.Host.Home = "/nonexistent/path/that/does/not/exist"
	env.Environ = map[string]string{
		"HOME": "/nonexistent/path/that/does/not/exist",
		"PATH": "/completely/garbage/path/that/does/not/exist",
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "garbage PATH should not crash")
}
