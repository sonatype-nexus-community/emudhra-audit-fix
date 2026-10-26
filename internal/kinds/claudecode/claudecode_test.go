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

package claudecode

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

func TestKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "claudecode", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Claude Code", k.Describe())
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
			k := New()
			got := k.Applicable(tt.host)
			assert.True(t, got.Applies)
			assert.Empty(t, got.Reason)
		})
	}
}

func TestKind_Audit_NotInstalled(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
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
	assert.Empty(t, findings, "no findings when Claude Code is not installed")
}

func TestKind_Audit_Behind(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	claudeDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))

	claudeBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.WriteFile(claudeBin, []byte("#!/bin/sh\necho '2.1.100'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": claudeDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Claude Code outputs just the version: "2.1.100"
		return exec.CommandResult{Stdout: "2.1.100\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for behind version")

	f := findings[0]
	assert.Equal(t, "claudecode", f.Kind)
	assert.Equal(t, "Claude Code", f.Tool)
	assert.Equal(t, "2.1.100", f.Version)
	assert.Equal(t, "2.1.303", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Equal(t, kinds.VersionBehind, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

	// Check guidance exactly as in the script (line 3229)
	assert.Equal(t, "claude update", f.GuidanceCompact)
	require.Len(t, f.GuidanceFull, 1)
	assert.Equal(t, "Upgrade Claude Code to 2.1.303 or later: claude update", f.GuidanceFull[0])
}

func TestKind_Audit_Fixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	claudeDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))

	claudeBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.WriteFile(claudeBin, []byte("#!/bin/sh\necho '2.1.303'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": claudeDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2.1.303\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for fixed version")

	f := findings[0]
	assert.Equal(t, "claudecode", f.Kind)
	assert.Equal(t, "2.1.303", f.Version)
	assert.Equal(t, "2.1.303", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
	assert.Equal(t, kinds.VersionOK, f.VersionCheck)
}

func TestKind_Audit_NewerThanFixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	claudeDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))

	claudeBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.WriteFile(claudeBin, []byte("#!/bin/sh\necho '2.2.0'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": claudeDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2.2.0\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "2.2.0", f.Version)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
}

func TestKind_Audit_VersionUnreadable(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	claudeDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))

	claudeBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.WriteFile(claudeBin, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": claudeDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{ExitCode: 1}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, kinds.StatusUnknown, f.Status())
	assert.Contains(t, f.Evidence, "version check failed")
}

func TestKind_Audit_MultipleCandidatePaths(t *testing.T) {
	// Claude Code has two candidate paths: .local/bin/claude and .claude/local/claude
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create one binary in .local/bin
	localBinDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(localBinDir, 0o755))

	localBin := filepath.Join(localBinDir, "claude")
	require.NoError(t, os.WriteFile(localBin, []byte("#!/bin/sh\necho '2.1.303'\n"), 0o755))

	// Create another binary in .claude/local
	claudeDir := filepath.Join(tempHome, ".claude", "local")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))

	claudeBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.WriteFile(claudeBin, []byte("#!/bin/sh\necho '2.1.200'\n"), 0o755))

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
		// First call for .local/bin (fixed), second for .claude/local (behind)
		version := "2.1.303"
		if callCount == 2 {
			version = "2.1.200"
		}
		return exec.CommandResult{Stdout: version + "\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Should find TWO binaries
	require.Len(t, findings, 2)
	// One should be fixed, one behind
	statuses := map[kinds.Status]bool{
		findings[0].Status(): true,
		findings[1].Status(): true,
	}
	assert.True(t, statuses[kinds.StatusLikelyOK], "one should be LIKELY-OK")
	assert.True(t, statuses[kinds.StatusLikelyAffected], "one should be LIKELY-AFFECTED")
}

func TestKind_Audit_DeduplicatesViaSymlink(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create a real binary
	localBinDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(localBinDir, 0o755))

	realBin := filepath.Join(localBinDir, "claude")
	require.NoError(t, os.WriteFile(realBin, []byte("#!/bin/sh\necho '2.1.303'\n"), 0o755))

	// Create symlink from .claude/local/claude to the same binary
	claudeDir := filepath.Join(tempHome, ".claude", "local")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))
	symlinkBin := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.Symlink(realBin, symlinkBin))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": "",
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2.1.303\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Both paths point to the same resolved binary, so should deduplicate to ONE finding
	assert.Len(t, findings, 1, "deduplicated by resolved path")
}

func TestKind_Audit_Hermetic(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "claudecode-hermetic-*")
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
	assert.Empty(t, findings, "hermetic test with no binaries should find nothing")
}

func TestKind_Audit_WithGarbageEnvironment(t *testing.T) {
	k := New()

	env := testutil.NewTestEnv()
	env.Host.Home = "/nonexistent"
	env.Environ = map[string]string{
		"HOME": "/nonexistent",
		"PATH": "/garbage/path",
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "garbage environment should not crash")
}
