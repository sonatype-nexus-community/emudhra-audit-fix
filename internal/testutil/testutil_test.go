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

package testutil

import (
	"context"
	"os"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestEnv(t *testing.T) {
	env := NewTestEnv()

	assert.NotNil(t, env)
	assert.Equal(t, "darwin", env.Host.OS)
	assert.Equal(t, "arm64", env.Host.Arch)
	assert.True(t, env.Host.HasTTY)

	assert.NotNil(t, env.Run)
	assert.NotNil(t, env.Probe)
	assert.NotNil(t, env.Prompt)
	assert.NotNil(t, env.Priv)
	assert.NotNil(t, env.Log)
	assert.NotNil(t, env.Backup)
}

func TestNewTestEnvWithHost(t *testing.T) {
	host := NewLinuxHost()
	env := NewTestEnvWithHost(host)

	assert.NotNil(t, env)
	assert.Equal(t, "linux", env.Host.OS)
	assert.Equal(t, "amd64", env.Host.Arch)
	assert.Equal(t, "ubuntu", env.Host.Distro.ID)
	assert.Equal(t, "debian", env.Host.Distro.IDLike)
}

func TestNewDarwinHost(t *testing.T) {
	host := NewDarwinHost()

	assert.Equal(t, "darwin", host.OS)
	assert.Equal(t, "arm64", host.Arch)
	assert.True(t, host.HasTTY)
	assert.False(t, host.IsRoot)
	assert.True(t, host.HasSudo)
}

func TestNewLinuxHost(t *testing.T) {
	host := NewLinuxHost()

	assert.Equal(t, "linux", host.OS)
	assert.Equal(t, "amd64", host.Arch)
	assert.True(t, host.HasTTY)
	assert.False(t, host.IsRoot)
	assert.True(t, host.HasSudo)
	assert.Equal(t, "ubuntu", host.Distro.ID)
	assert.Equal(t, "debian", host.Distro.IDLike)
	assert.Equal(t, "22.04", host.Distro.Version)
}

func TestNewRootHost(t *testing.T) {
	host := NewRootHost()

	assert.True(t, host.IsRoot)
	assert.Equal(t, "darwin", host.OS)
}

func TestTempHome(t *testing.T) {
	home, err := TempHome()
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(home) }()

	// Verify the directory exists
	info, err := os.Stat(home)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Verify it's under the temp directory
	assert.Contains(t, home, os.TempDir())
}

func TestAssertFileExists(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "testutil-*")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	// Test with existing file
	mockT := &mockTestingT{}
	AssertFileExists(mockT, tmpPath)
	assert.False(t, mockT.failed, "Should not fail for existing file")

	// Test with non-existing file
	mockT = &mockTestingT{}
	AssertFileExists(mockT, "/nonexistent/file/path")
	assert.True(t, mockT.failed, "Should fail for non-existing file")
}

// mockTestingT implements the minimal interface needed for AssertFileExists
type mockTestingT struct {
	failed bool
}

func (m *mockTestingT) Errorf(format string, args ...interface{}) {
	m.failed = true
}

func TestFakeRunner(t *testing.T) {
	runner := FakeRunner()
	assert.NotNil(t, runner)

	// Verify it can be used
	ctx := context.Background()
	result := runner.Run(ctx, "echo", "test")
	assert.NotNil(t, result)
}

func TestFakeEngine(t *testing.T) {
	engine := FakeEngine()
	assert.NotNil(t, engine)
}

func TestFakePrompter(t *testing.T) {
	prompter := FakePrompter()
	assert.NotNil(t, prompter)
}

func TestFakeEscalator(t *testing.T) {
	escalator := FakeEscalator()
	assert.NotNil(t, escalator)
}

func TestFakeStore(t *testing.T) {
	store := FakeStore()
	assert.NotNil(t, store)
}

func TestSetenv(t *testing.T) {
	// Set a test variable
	key := "TESTUTIL_TEST_VAR"
	cleanup := Setenv(key, "test-value")
	defer cleanup()

	// Verify the value was set
	value := os.Getenv(key)
	assert.Equal(t, "test-value", value)

	// Call cleanup
	cleanup()

	// Verify it was restored (unset)
	value = os.Getenv(key)
	assert.Empty(t, value)
}

func TestSetenv_Overwrites(t *testing.T) {
	// Set an initial value
	key := "TESTUTIL_OVERWRITE_VAR"
	originalCleanup := Setenv(key, "original")
	defer originalCleanup()

	// Overwrite with new value
	secondCleanup := Setenv(key, "new-value")
	value := os.Getenv(key)
	assert.Equal(t, "new-value", value)

	// Restore to "original"
	secondCleanup()
	value = os.Getenv(key)
	assert.Equal(t, "original", value)

	// Clean up completely
	originalCleanup()
	value = os.Getenv(key)
	assert.Empty(t, value)
}

func TestContext(t *testing.T) {
	ctx := Context()
	assert.NotNil(t, ctx)
	assert.Equal(t, context.Background(), ctx)
}

// Integration test to verify all builders work together
func TestTestEnvIntegration(t *testing.T) {
	env := NewTestEnv()

	// Verify all components are properly initialized and not nil
	require.NotNil(t, env.Run)
	require.NotNil(t, env.Probe)
	require.NotNil(t, env.Prompt)
	require.NotNil(t, env.Priv)
	require.NotNil(t, env.Backup)

	// Verify the host is properly configured
	require.Equal(t, "darwin", env.Host.OS)

	// Test that components can be used (no panics)
	ctx := context.Background()

	// Test fake runner
	result := env.Run.Run(ctx, "test", "command")
	assert.NotNil(t, result)

	// Test fake backup
	backupPath, err := env.Backup.Create("/test/file", "test")
	assert.NoError(t, err)
	assert.NotEmpty(t, backupPath)
}

func TestHostBuildersComposition(t *testing.T) {
	// Test that we can compose different host configurations
	tests := []struct {
		name   string
		host   func() platform.Host
		os     string
		arch   string
		isRoot bool
	}{
		{
			name:   "darwin host",
			host:   NewDarwinHost,
			os:     "darwin",
			arch:   "arm64",
			isRoot: false,
		},
		{
			name:   "linux host",
			host:   NewLinuxHost,
			os:     "linux",
			arch:   "amd64",
			isRoot: false,
		},
		{
			name:   "root host",
			host:   NewRootHost,
			os:     "darwin",
			arch:   "arm64",
			isRoot: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := tt.host()
			assert.Equal(t, tt.os, host.OS)
			assert.Equal(t, tt.arch, host.Arch)
			assert.Equal(t, tt.isRoot, host.IsRoot)
		})
	}
}

func TestNewTestEnvIsHermetic(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/Users/someone")
	env := NewTestEnv()
	assert.Equal(t, "", env.Path(), "a test env must not see the real PATH")
	assert.Equal(t, "", env.Home(), "a test env must not see the real HOME")
}

func TestNewTestEnvHasATempDir(t *testing.T) {
	env := NewTestEnv()
	assert.NotEmpty(t, env.TempDir, "an empty TempDir makes Kinds write probe files into the source directory")
	assert.DirExists(t, env.TempDir)

	env2 := NewTestEnvT(t)
	assert.NotEmpty(t, env2.TempDir)
	assert.NotEqual(t, env.TempDir, env2.TempDir)
}
