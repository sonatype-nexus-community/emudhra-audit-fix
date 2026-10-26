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

package pixi

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
	assert.Equal(t, "pixi", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Pixi package manager", k.Describe())
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

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
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
	assert.Empty(t, findings, "no findings when pixi is not installed")
}

func TestKind_Audit_Behind(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	pixiDir := filepath.Join(tempHome, ".pixi", "bin")
	require.NoError(t, os.MkdirAll(pixiDir, 0o755))

	pixiBin := filepath.Join(pixiDir, "pixi")
	require.NoError(t, os.WriteFile(pixiBin, []byte("#!/bin/sh\necho 'pixi 0.80.0'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": pixiDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "pixi 0.80.0\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for behind version")

	f := findings[0]
	assert.Equal(t, "pixi", f.Kind)
	assert.Equal(t, "pixi", f.Tool, "Tool name should match script's $label")
	assert.Equal(t, "0.80.0", f.Version)
	assert.Equal(t, "0.82.1", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status())
	assert.Equal(t, kinds.VersionBehind, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)

	// Check guidance exactly as in the script (line 3227)
	assert.Equal(t, "pixi self-update   (or: brew upgrade pixi)", f.GuidanceCompact)
	require.Len(t, f.GuidanceFull, 1)
	assert.Equal(t, "Upgrade pixi to 0.82.1 or later: pixi self-update", f.GuidanceFull[0])
}

func TestKind_Audit_Fixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	pixiDir := filepath.Join(tempHome, ".pixi", "bin")
	require.NoError(t, os.MkdirAll(pixiDir, 0o755))

	pixiBin := filepath.Join(pixiDir, "pixi")
	require.NoError(t, os.WriteFile(pixiBin, []byte("#!/bin/sh\necho 'pixi 0.82.1'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": pixiDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "pixi 0.82.1\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one finding for fixed version")

	f := findings[0]
	assert.Equal(t, "pixi", f.Kind)
	assert.Equal(t, "0.82.1", f.Version)
	assert.Equal(t, "0.82.1", f.FixedVersion)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
	assert.Equal(t, kinds.VersionOK, f.VersionCheck)
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
}

func TestKind_Audit_NewerThanFixed(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	pixiDir := filepath.Join(tempHome, ".pixi", "bin")
	require.NoError(t, os.MkdirAll(pixiDir, 0o755))

	pixiBin := filepath.Join(pixiDir, "pixi")
	require.NoError(t, os.WriteFile(pixiBin, []byte("#!/bin/sh\necho 'pixi 1.0.0'\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": pixiDir,
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "pixi 1.0.0\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "1.0.0", f.Version)
	assert.Equal(t, kinds.StatusLikelyOK, f.Status())
}

func TestKind_Audit_VersionUnreadable(t *testing.T) {
	k := New()

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	pixiDir := filepath.Join(tempHome, ".pixi", "bin")
	require.NoError(t, os.MkdirAll(pixiDir, 0o755))

	pixiBin := filepath.Join(pixiDir, "pixi")
	require.NoError(t, os.WriteFile(pixiBin, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": pixiDir,
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

	tempHome, err := os.MkdirTemp("", "pixi-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	// Create a real binary in .pixi/bin
	pixiDir := filepath.Join(tempHome, ".pixi", "bin")
	require.NoError(t, os.MkdirAll(pixiDir, 0o755))

	realBin := filepath.Join(pixiDir, "pixi")
	require.NoError(t, os.WriteFile(realBin, []byte("#!/bin/sh\necho 'pixi 0.82.1'\n"), 0o755))

	// Create a symlink from PATH to the same binary
	linkDir := filepath.Join(tempHome, "bin")
	require.NoError(t, os.MkdirAll(linkDir, 0o755))
	linkBin := filepath.Join(linkDir, "pixi")
	require.NoError(t, os.Symlink(realBin, linkBin))

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": linkDir, // PATH has the symlink
	}

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		return exec.CommandResult{Stdout: "pixi 0.82.1\n", ExitCode: 0}
	}
	env.Run = runner

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	// Both the symlink and the real binary point to the same resolved path
	// So we should get only ONE finding
	assert.Len(t, findings, 1, "deduplicated by resolved path")
}

func TestKind_Audit_Hermetic(t *testing.T) {
	// Verify that tests are hermetic: no real PATH or HOME leakage
	k := New()

	tempHome, err := os.MkdirTemp("", "pixi-hermetic-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempHome) }()

	env := testutil.NewTestEnv()
	env.Host.Home = tempHome
	env.Environ = map[string]string{
		"HOME": tempHome,
		"PATH": "", // Empty PATH
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "hermetic test with no binaries should find nothing")
}

func TestKind_Audit_WithGarbageEnvironment(t *testing.T) {
	// Test with HOME and PATH set to garbage to verify hermeticity
	k := New()

	env := testutil.NewTestEnv()
	env.Host.Home = "/nonexistent/path"
	env.Environ = map[string]string{
		"HOME": "/nonexistent/path",
		"PATH": "/garbage/path/that/does/not/exist",
	}

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "garbage environment should not crash")
}
