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

// Package testutil provides test helpers: fake Runner, temp-HOME helper, fixture CA bundles.
package testutil

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/backup"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
)

// NewTestEnv creates an Env populated with fake implementations for testing.
func NewTestEnv() *kinds.Env {
	// Env.TempDir must never be empty: a Kind that writes a probe file with
	// filepath.Join(env.TempDir, name) would otherwise write into the current
	// directory, which during `go test` is the package's source directory.
	// There is no *testing.T here to register a cleanup, so the directory is
	// left to the OS temp cleaner; prefer NewTestEnvT in new tests.
	dir, err := os.MkdirTemp("", "emudhra-test-")
	if err != nil {
		panic(err)
	}
	return &kinds.Env{
		TempDir: dir,
		Host:    platform.Host{OS: "darwin", Arch: "arm64", HasTTY: true},
		Run:     exec.NewFakeRunner(),
		Probe:   probe.NewFakeEngine(),
		Prompt:  prompt.NewFakePrompter(),
		Priv:    privilege.NewFakeEscalator(),
		Log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Backup:  backup.NewFakeStore(),
		// Hermetic by default: an empty environment means no PATH and no
		// HOME, so a Kind under test cannot discover the developer's real
		// installs. Tests that need discovery point HOME and PATH at a temp
		// directory with Env.Environ.
		Environ: map[string]string{},
	}
}

// NewTestEnvWithHost creates an Env with a specific Host configuration.
func NewTestEnvWithHost(host platform.Host) *kinds.Env {
	env := NewTestEnv()
	env.Host = host
	return env
}

// NewDarwinHost creates a macOS Host for testing.
func NewDarwinHost() platform.Host {
	return platform.Host{
		OS:      "darwin",
		Arch:    "arm64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
	}
}

// NewLinuxHost creates a Linux Host for testing.
func NewLinuxHost() platform.Host {
	return platform.Host{
		OS:      "linux",
		Arch:    "amd64",
		HasTTY:  true,
		IsRoot:  false,
		HasSudo: true,
		Distro: platform.Distro{
			ID:      "ubuntu",
			IDLike:  "debian",
			Version: "22.04",
		},
		Family: platform.FamilyDebian,
	}
}

// NewRootHost creates a Host running as root.
func NewRootHost() platform.Host {
	host := NewDarwinHost()
	host.IsRoot = true
	return host
}

// TempHome creates a temporary HOME directory and returns its path.
// The caller is responsible for cleaning it up.
func TempHome() (string, error) {
	return os.MkdirTemp("", "emudhra-test-home-*")
}

// AssertFileExists asserts that a file exists.
func AssertFileExists(t interface {
	Errorf(format string, args ...interface{})
}, path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file to exist: %s", path)
	}
}

// FakeRunner returns a new exec.FakeRunner.
func FakeRunner() *exec.FakeRunner {
	return exec.NewFakeRunner()
}

// FakeEngine returns a new probe.FakeEngine.
func FakeEngine() *probe.FakeEngine {
	return probe.NewFakeEngine()
}

// FakePrompter returns a new prompt.FakePrompter.
func FakePrompter() *prompt.FakePrompter {
	return prompt.NewFakePrompter()
}

// FakeEscalator returns a new privilege.FakeEscalator.
func FakeEscalator() *privilege.FakeEscalator {
	return privilege.NewFakeEscalator()
}

// FakeStore returns a new backup.FakeStore.
func FakeStore() *backup.FakeStore {
	return backup.NewFakeStore()
}

// Setenv sets an environment variable and returns a cleanup function.
func Setenv(key, value string) func() {
	old := os.Getenv(key)
	_ = os.Setenv(key, value)
	return func() {
		if old == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, old)
		}
	}
}

// Context returns a background context for tests.
func Context() context.Context {
	return context.Background()
}

// NewTestEnvT is NewTestEnv with a TempDir that the test framework removes
// when the test ends.
func NewTestEnvT(t testing.TB) *kinds.Env {
	t.Helper()
	env := NewTestEnv()
	_ = os.RemoveAll(env.TempDir)
	env.TempDir = t.TempDir()
	env.Root = t.TempDir() // the host's own /usr/local, /opt/homebrew and /usr/lib/jvm are invisible
	return env
}
