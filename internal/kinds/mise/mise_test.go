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

package mise

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
	assert.Equal(t, "mise", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Mise tool version manager", k.Describe())
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

	tempHome, err := os.MkdirTemp("", "mise-test-*")
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
	assert.Empty(t, findings, "no findings when mise is not installed")
}

func TestKind_Audit_Behind(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	miseBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\necho '2026.10.01 linux-arm64'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": miseDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mise outputs: "2026.10.01 linux-arm64 (2024-10-23)" (first field is version)
		return exec.CommandResult{Stdout: "2026.10.01 linux-arm64\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for behind version")

	f := findings[0]
	assert.Equal(t, "mise", f.Kind)
	assert.Equal(t, "mise", f.Tool, "Tool name should match script's $label")
	assert.Equal(t, "2026.10.01", f.Version)
	assert.Equal(t, "2026.10.17", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Equal(t, kinds.VersionBehind, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

	// Check guidance exactly as in the script (line 3228)
	assert.Equal(t, "mise self-update   (or: brew upgrade mise)", f.GuidanceCompact)
	require.Len(t, f.GuidanceFull, 1)
	assert.Equal(t, "Upgrade mise to 2026.10.17 or later: mise self-update", f.GuidanceFull[0])
}

func TestKind_Audit_Fixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	miseBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\necho '2026.10.17 linux-arm64'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": miseDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2026.10.17 linux-arm64\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for fixed version")

	f := findings[0]
	assert.Equal(t, "mise", f.Kind)
	assert.Equal(t, "2026.10.17", f.Version)
	assert.Equal(t, "2026.10.17", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
	assert.Equal(t, kinds.VersionOK, f.VersionCheck)
}

func TestKind_Audit_NewerThanFixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	miseBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\necho '2026.11.01 linux-arm64'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": miseDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2026.11.01 linux-arm64\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "2026.11.01", f.Version)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
}

func TestKind_Audit_VersionUnreadable(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	miseBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": miseDir,
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

func TestKind_Audit_MultipleCandidatePaths_Deduplicates(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create a real binary in .local/bin
	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	realBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(realBin, []byte("#!/bin/sh\necho '2026.10.17 linux-arm64'\n"), 0o755))

	// Create a symlink from PATH to the same binary
	linkDir := filepath.Join(tempHome, "bin")
	require.NoError(t, os.MkdirAll(linkDir, 0o755))
	linkBin := filepath.Join(linkDir, "mise")
	require.NoError(t, os.Symlink(realBin, linkBin))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": linkDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "2026.10.17 linux-arm64\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Both the symlink and the real binary point to the same resolved path
	assert.Len(t, findings, 1, "deduplicated by resolved path")
}

func TestKind_Audit_VersionFormat(t *testing.T) {
	// Test that mise's version extraction (first field) works correctly
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	miseDir := filepath.Join(tempHome, ".local", "bin")
	require.NoError(t, os.MkdirAll(miseDir, 0o755))

	miseBin := filepath.Join(miseDir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\necho '2026.10.17 linux-arm64 (2024-10-23)'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": miseDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Real mise output format: version platform (date)
		return exec.CommandResult{Stdout: "2026.10.17 linux-arm64 (2024-10-23)\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify version was extracted as first field
	assert.Equal(t, "2026.10.17", findings[0].Version)
}

func TestKind_Audit_Hermetic(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "mise-hermetic-*")
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
