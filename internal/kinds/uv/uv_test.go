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

package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// TestInstallMethod tests the installMethod function for various installation layouts.
// This ports the scenario checks from legacy/tests/test_fix_uv.sh.
func TestInstallMethod(t *testing.T) {
	tests := []struct {
		name     string
		binPath  string
		setup    func(home string) error
		expected string
	}{
		{
			name:     "standalone with receipt",
			binPath:  "$HOME/.local/bin/uv",
			setup:    setupStandaloneReceipt,
			expected: "standalone",
		},
		{
			name:     "Homebrew Cellar",
			binPath:  "$HOME/opt/homebrew/Cellar/uv/0.9.0/bin/uv",
			expected: "brew",
		},
		{
			name:     "pipx",
			binPath:  "$HOME/.local/pipx/venvs/uv/bin/uv",
			expected: "pipx",
		},
		{
			name:     "cargo",
			binPath:  "$HOME/.cargo/bin/uv",
			expected: "cargo",
		},
		{
			name:     "mise",
			binPath:  "$HOME/.local/share/mise/installs/uv/0.9.0/bin/uv",
			expected: "mise",
		},
		{
			name:     "asdf",
			binPath:  "$HOME/.asdf/installs/uv/0.9.0/bin/uv",
			expected: "asdf",
		},
		{
			name:     "unknown",
			binPath:  "$HOME/bin/uv",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			binPath := strings.ReplaceAll(tt.binPath, "$HOME", home)

			// Create the binary file
			err := os.MkdirAll(filepath.Dir(binPath), 0755)
			if err != nil {
				t.Fatal(err)
			}
			err = os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0755)
			if err != nil {
				t.Fatal(err)
			}

			// Run setup if provided
			if tt.setup != nil {
				err = tt.setup(home)
				if err != nil {
					t.Fatal(err)
				}
			}

			env := &kinds.Env{
				Environ: map[string]string{
					"HOME":            home,
					"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
				},
			}

			result := installMethod(binPath, env)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// setupStandaloneReceipt creates a uv-receipt.json for a standalone install.
func setupStandaloneReceipt(home string) error {
	receiptDir := filepath.Join(home, ".config", "uv")
	if err := os.MkdirAll(receiptDir, 0755); err != nil {
		return err
	}

	binDir := filepath.Join(home, ".local", "bin")
	receipt := `{"binaries":["uv"],"install_prefix":"` + binDir + `"}`

	return os.WriteFile(filepath.Join(receiptDir, "uv-receipt.json"), []byte(receipt), 0644)
}

// TestUpgradeCmd tests the upgradeCmd function for various install methods.
func TestUpgradeCmd(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"standalone", "uv self update"},
		{"brew", "brew upgrade uv"},
		{"pipx", "pipx upgrade uv"},
		{"pip", "pip install --upgrade uv   (in the environment that owns it)"},
		{"cargo", "cargo install --locked --force uv"},
		{"mise", "mise use -g uv@latest   (mise manages this uv)"},
		{"asdf", "asdf install uv latest && asdf global uv latest"},
		{"unknown", "uv self update   (standalone install), or your package manager: brew upgrade uv / pipx upgrade uv"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := upgradeCmd(tt.method)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestAudit tests the Audit function with various uv installations.
func TestAudit(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		hasFix         bool
		expectedStatus kinds.Status
	}{
		{
			name:           "version behind, standalone",
			version:        "0.9.0",
			hasFix:         true,
			expectedStatus: kinds.StatusLikelyAffected,
		},
		{
			name:           "version fixed",
			version:        "0.13.4",
			hasFix:         false,
			expectedStatus: kinds.StatusLikelyOK,
		},
		{
			name:           "version ahead",
			version:        "0.14.0",
			hasFix:         false,
			expectedStatus: kinds.StatusLikelyOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()

			// Create a stub uv binary
			uvBin := filepath.Join(home, ".local", "bin", "uv")
			err := os.MkdirAll(filepath.Dir(uvBin), 0755)
			if err != nil {
				t.Fatal(err)
			}

			stub := createStubUVBinary(tt.version, "")
			err = os.WriteFile(uvBin, []byte(stub), 0755)
			if err != nil {
				t.Fatal(err)
			}

			// Create standalone receipt
			err = setupStandaloneReceipt(home)
			if err != nil {
				t.Fatal(err)
			}

			// Create environment
			env := &kinds.Env{
				Host: platform.Host{OS: "darwin"},
				Run:  exec.NewRealRunner(),
				Environ: map[string]string{
					"HOME":            home,
					"PATH":            filepath.Dir(uvBin),
					"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
				},
			}

			// Run audit
			k := New()
			findings, err := k.Audit(context.Background(), env)
			if err != nil {
				t.Fatalf("Audit failed: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}

			f := findings[0]
			if f.Kind != kindID {
				t.Errorf("expected Kind %s, got %s", kindID, f.Kind)
			}
			if f.Tool != "uv" {
				t.Errorf("expected Tool uv, got %s", f.Tool)
			}
			if f.Version != tt.version {
				t.Errorf("expected Version %s, got %s", tt.version, f.Version)
			}
			if f.Status() != tt.expectedStatus {
				t.Errorf("expected Status %v, got %v", tt.expectedStatus, f.Status())
			}
			if f.HasFix != tt.hasFix {
				t.Errorf("expected HasFix %v, got %v", tt.hasFix, f.HasFix)
			}
			if f.ProbeResult != kinds.ProbeSkipped || f.Evidence != kinds.VersionOnlyProbeReason {
				t.Errorf("the probe line must read the script's text, got %v %q", f.ProbeResult, f.Evidence)
			}
		})
	}
}

// TestAuditNoUv tests that audit returns no findings when uv is not installed.
func TestAuditNoUv(t *testing.T) {
	home := t.TempDir()

	env := &kinds.Env{
		Host: platform.Host{OS: "darwin"},
		Run:  exec.NewRealRunner(),
		Environ: map[string]string{
			"HOME": home,
			"PATH": "",
		},
	}

	k := New()
	findings, err := k.Audit(context.Background(), env)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// TestUVFix ports the test scenarios from legacy/tests/test_fix_uv.sh.
// Each t.Run name matches the shell test scenario name.
func TestUVFix(t *testing.T) {
	t.Run("standalone install answer y", func(t *testing.T) {
		// Scenario 1: standalone install, answer y -> Changed
		env := testutil.NewTestEnvT(t)

		// Track version and calls
		callCount := 0

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) {
				callCount++
				if len(args) > 0 && args[0] == "--version" {
					// First 2 calls (audit + backup check) return old version
					// After that (post-update) return new version
					if callCount <= 2 {
						return exec.CommandResult{Stdout: "uv 0.9.0"}
					}
					return exec.CommandResult{Stdout: "uv 0.13.4"}
				}
				if len(args) >= 2 && args[0] == "self" && args[1] == "update" {
					return exec.CommandResult{Stdout: "uv updated"}
				}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Setup standalone install
		setupStandaloneEnv(t, env)

		// Run audit and plan
		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if len(fixes) != 1 {
			t.Fatalf("expected 1 fix, got %d", len(fixes))
		}

		// Run the fix
		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: true},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(context.Background(), s)

		// Check outcome
		if result != fixrun.Changed {
			t.Errorf("expected Changed, got %v", result)
		}

		// Check output
		output := out.String()
		if !strings.Contains(output, "0.13.4") {
			t.Errorf("expected output to mention new version 0.13.4, got:\n%s", output)
		}
		if !strings.Contains(output, "version check, not a TLS probe") {
			t.Errorf("expected 'version check, not a TLS probe' in output, got:\n%s", output)
		}
		if !strings.Contains(output, "Python versions and tools") {
			t.Errorf("expected 'Python versions and tools' in output, got:\n%s", output)
		}
	})

	t.Run("decline", func(t *testing.T) {
		// Scenario 2: answer n -> Skipped
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv 0.9.0"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		setupStandaloneEnv(t, env)

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		// Run with declined prompt
		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: false},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(context.Background(), s)

		if result != fixrun.Skipped {
			t.Errorf("expected Skipped, got %v", result)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		// Scenario 3: dry run prints the command, changes nothing
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv 0.9.0"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		setupStandaloneEnv(t, env)

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		// Run in dry-run mode
		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: true},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  true,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(context.Background(), s)

		if result != fixrun.Skipped {
			t.Errorf("expected Skipped, got %v", result)
		}

		// Check output contains the command
		output := out.String()
		if !strings.Contains(output, "self update") {
			t.Errorf("expected 'self update' in output, got:\n%s", output)
		}
	})

	t.Run("Homebrew install", func(t *testing.T) {
		// Scenario 4: Homebrew install never runs self update
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv 0.9.0"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Setup brew-style path
		brewDir := filepath.Join(env.TempDir, "opt", "homebrew", "Cellar", "uv", "0.9.0", "bin")
		env.Environ["PATH"] = brewDir
		env.Environ["HOME"] = env.TempDir

		uvPath := filepath.Join(brewDir, "uv")
		if err := os.MkdirAll(filepath.Dir(uvPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(uvPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		// The install must be FOUND and reported (so the user is told what to
		// run), but it must not be marked fixable: self update is for the
		// standalone installer only. Asserting this on the finding, and not just
		// on an empty plan, stops an audit that finds nothing from passing.
		if len(findings) != 1 {
			t.Fatalf("expected the install to be found, got %d findings", len(findings))
		}
		if findings[0].HasFix {
			t.Errorf("a homebrew uv must not be marked fixable")
		}
		if got := findings[0].Status(); got != kinds.StatusLikelyAffected {
			t.Errorf("expected LIKELY-AFFECTED for an old uv, got %s", got)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		// No fixes should be scheduled for Homebrew install
		if len(fixes) != 0 {
			t.Errorf("expected 0 fixes for Homebrew install, got %d", len(fixes))
		}
	})

	t.Run("pipx install", func(t *testing.T) {
		// Scenario 5: pipx install never runs self update
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv 0.9.0"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Setup pipx-style path
		pipxDir := filepath.Join(env.TempDir, ".local", "pipx", "venvs", "uv", "bin")
		env.Environ["PATH"] = pipxDir
		env.Environ["HOME"] = env.TempDir

		uvPath := filepath.Join(pipxDir, "uv")
		if err := os.MkdirAll(filepath.Dir(uvPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(uvPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		// The install must be FOUND and reported (so the user is told what to
		// run), but it must not be marked fixable: self update is for the
		// standalone installer only. Asserting this on the finding, and not just
		// on an empty plan, stops an audit that finds nothing from passing.
		if len(findings) != 1 {
			t.Fatalf("expected the install to be found, got %d findings", len(findings))
		}
		if findings[0].HasFix {
			t.Errorf("a pipx uv must not be marked fixable")
		}
		if got := findings[0].Status(); got != kinds.StatusLikelyAffected {
			t.Errorf("expected LIKELY-AFFECTED for an old uv, got %s", got)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		// No fixes should be scheduled for pipx install
		if len(fixes) != 0 {
			t.Errorf("expected 0 fixes for pipx install, got %d", len(fixes))
		}
	})

	t.Run("cargo install", func(t *testing.T) {
		// Additional scenario: cargo install never runs self update
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv 0.9.0"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Setup cargo-style path
		cargoDir := filepath.Join(env.TempDir, ".cargo", "bin")
		env.Environ["PATH"] = cargoDir
		env.Environ["HOME"] = env.TempDir

		uvPath := filepath.Join(cargoDir, "uv")
		if err := os.MkdirAll(filepath.Dir(uvPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(uvPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		// The install must be FOUND and reported (so the user is told what to
		// run), but it must not be marked fixable: self update is for the
		// standalone installer only. Asserting this on the finding, and not just
		// on an empty plan, stops an audit that finds nothing from passing.
		if len(findings) != 1 {
			t.Fatalf("expected the install to be found, got %d findings", len(findings))
		}
		if findings[0].HasFix {
			t.Errorf("a cargo uv must not be marked fixable")
		}
		if got := findings[0].Status(); got != kinds.StatusLikelyAffected {
			t.Errorf("expected LIKELY-AFFECTED for an old uv, got %s", got)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		// No fixes should be scheduled for cargo install
		if len(fixes) != 0 {
			t.Errorf("expected 0 fixes for cargo install, got %d", len(fixes))
		}
	})

	t.Run("failed update", func(t *testing.T) {
		// Scenario 6: update that does nothing leaves the working binary and counts as failed
		// The binary still works - NO restore should happen
		env := testutil.NewTestEnvT(t)

		version := "0.9.0"
		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				// Version stays the same
				return exec.CommandResult{Stdout: "uv " + version}
			}
			if isUVCommand(name) && len(args) >= 2 && args[0] == "self" && args[1] == "update" {
				// Update does nothing
				return exec.CommandResult{Stdout: "info: checking for updates"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		setupStandaloneEnv(t, env)

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: true},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(context.Background(), s)

		// Should report failure
		if result != fixrun.Failed {
			t.Errorf("expected Failed for no-op update, got %v", result)
		}

		// Check output mentions "still behind"
		output := out.String()
		if !strings.Contains(output, "still behind") {
			t.Errorf("expected 'still behind' in output, got:\n%s", output)
		}

		// Check that NO restore happened (the binary still works)
		// A restore would be: "cp -p BACKUP ORIGINAL"
		// The code uses s.Run.Run directly for cp commands
		// So we check that the output doesn't contain the restore message
		if strings.Contains(output, "restoring the previous binary") {
			t.Error("should NOT have restored the binary in the still-behind case")
		}
	})

	t.Run("broken update", func(t *testing.T) {
		// Scenario 7: update that breaks the binary is rolled back
		env := testutil.NewTestEnvT(t)

		calls := 0

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			calls++
			if isUVCommand(name) {
				if len(args) > 0 && args[0] == "--version" {
					// First call (audit) returns OK, subsequent calls (after break) fail
					if calls > 2 {
						return exec.CommandResult{ExitCode: 1, Error: fmt.Errorf("broken binary")}
					}
					return exec.CommandResult{Stdout: "uv 0.9.0"}
				}
				if len(args) >= 2 && args[0] == "self" && args[1] == "update" {
					// Update breaks the binary
					return exec.CommandResult{Stdout: "uv updated"}
				}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		setupStandaloneEnv(t, env)

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: true},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		result := fixes[0].Run(context.Background(), s)

		// Should report failure
		if result != fixrun.Failed {
			t.Errorf("expected Failed for broken binary, got %v", result)
		}

		// Check output mentions rollback
		output := out.String()
		if !strings.Contains(output, "no longer reports a version") {
			t.Errorf("expected 'no longer reports a version' in output, got:\n%s", output)
		}

		// The message is not enough: the previous binary must actually be put
		// back, a cp -p of the backup over the original.
		restored := false
		for _, c := range runner.Commands {
			if strings.HasPrefix(c, "cp -p ") && strings.Contains(c, "uv.bak") && strings.HasSuffix(c, " "+findings[0].Path) {
				restored = true
			}
		}
		if !restored {
			t.Errorf("the previous binary was not restored; commands run: %q", runner.Commands)
		}
		if !strings.Contains(output, "restoring the previous binary") {
			t.Errorf("expected 'restoring the previous binary' in output, got:\n%s", output)
		}

		// The restore happens via s.Run.Run, so we check the actual binary file
		// In the fake runner, the restore is the second cp -p command
		// We verify this by checking that the output indicates the restore happened
	})

	t.Run("mutation: still-behind must not restore", func(t *testing.T) {
		// Mutation g: restore in the still-behind case must be caught
		// This verifies that when the version is still behind, NO cp -p restore runs
		env := testutil.NewTestEnvT(t)

		version := "0.9.0"
		var cpCalls []string

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isUVCommand(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "uv " + version}
			}
			if isUVCommand(name) && len(args) >= 2 && args[0] == "self" && args[1] == "update" {
				// Simulate failed update
				return exec.CommandResult{Stdout: "no update available"}
			}
			if name == "cp" {
				cpCalls = append(cpCalls, strings.Join(args, " "))
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		setupStandaloneEnv(t, env)

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true
		s := &fixrun.Session{
			Run:     runner,
			Prompt:  &testPrompt{answer: true},
			Priv:    fakePriv,
			Host:    platform.Host{OS: "darwin"},
			DryRun:  false,
			Yes:     false,
			Color:   false,
			Out:     &out,
			Stamp:   "20260101120000",
			TempDir: env.TempDir,
		}

		_ = fixes[0].Run(context.Background(), s)

		// In the still-behind case, there should be only ONE cp -p call (the backup)
		// NOT a second call that would be the restore
		restoreCount := 0
		for _, call := range cpCalls {
			// A restore would have the backup as source and original as destination
			// Format: "-p /path/to/uv /path/to/uv.bak" (backup)
			//         "-p /path/to/uv.bak /path/to/uv" (restore)
			if strings.Contains(call, "uv.bak") && !strings.HasSuffix(call, "uv.bak") {
				// This is a restore (backup file is source, not destination)
				restoreCount++
			}
		}

		if restoreCount > 0 {
			t.Errorf("expected NO restore cp -p call in still-behind case, but found %d restore(s). cp calls: %v", restoreCount, cpCalls)
		}
	})
}

// isUVCommand checks if a command is uv (handles full paths)
func isUVCommand(name string) bool {
	return strings.Contains(name, "uv") && !strings.Contains(name, "uv.bak")
}

// setupStandaloneEnv creates a standalone uv installation environment
func setupStandaloneEnv(t *testing.T, env *kinds.Env) {
	// Create standalone install directory
	binDir := filepath.Join(env.TempDir, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	uvPath := filepath.Join(binDir, "uv")
	stub := createStubUVBinary("0.9.0", env.TempDir)
	if err := os.WriteFile(uvPath, []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}

	// Create receipt
	if err := setupStandaloneReceipt(env.TempDir); err != nil {
		t.Fatal(err)
	}

	// Set environment
	env.Environ["HOME"] = env.TempDir
	env.Environ["PATH"] = binDir
	env.Environ["XDG_CONFIG_HOME"] = filepath.Join(env.TempDir, ".config")
}

// createStubUVBinary creates a stub shell script that outputs a fixed version.
// When testDir is provided, it creates a version tracking file.
func createStubUVBinary(version, testDir string) string {
	if testDir != "" {
		// Create a more sophisticated stub that tracks calls
		return `#!/bin/sh
case "$1" in
  --version) echo "uv ` + version + `" ;;
  self) echo "self $*" >> "` + testDir + `/calls" ;;
esac
`
	}
	return `#!/bin/sh
case "$1" in
  --version) echo "uv ` + version + `" ;;
esac
`
}

// testPrompt implements prompt.Prompter for testing.
type testPrompt struct {
	answer bool
}

func (p *testPrompt) Confirm(question string, autoYes bool) bool {
	return p.answer || autoYes
}

func (p *testPrompt) ConfirmAgree(warning string) bool {
	return false
}
