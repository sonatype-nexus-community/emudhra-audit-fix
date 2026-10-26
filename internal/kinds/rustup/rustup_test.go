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

package rustup

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

// isRustupCmd checks if a command is rustup (handles full paths)
func isRustupCmd(name string) bool {
	return strings.Contains(name, "rustup")
}

// TestRustupAudit tests the Audit function.
func TestRustupAudit(t *testing.T) {
	t.Run("finds rustup in CARGO_HOME", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Mock rustup responses
		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Set CARGO_HOME and PATH
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		// Create empty rustup file so discover.Executables finds it
		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		// Run audit
		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		if len(findings) == 0 {
			t.Fatal("expected at least one finding")
		}

		// Check that we found rustup
		f := findings[0]
		if f.Kind != "rustup" {
			t.Errorf("expected Kind rustup, got %s", f.Kind)
		}
		if f.Version != "1.28.0" {
			t.Errorf("expected Version 1.28.0, got %s", f.Version)
		}
		if f.VersionCheck != kinds.VersionBehind {
			t.Errorf("expected VersionCheck behind, got %v", f.VersionCheck)
		}
	})

	t.Run("detects fixed version", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.29.2 (abc123 2026-01-01)"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		if len(findings) == 0 {
			t.Fatal("expected at least one finding")
		}

		f := findings[0]
		if f.ProbeResult != kinds.ProbeSkipped || f.Evidence != kinds.VersionOnlyProbeReason {
			t.Errorf("the probe line must read the script's text, got %v %q", f.ProbeResult, f.Evidence)
		}
		if f.VersionCheck != kinds.VersionOK {
			t.Errorf("expected VersionOK, got %v", f.VersionCheck)
		}
	})

	t.Run("detects brew install", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Use a Homebrew-style path
		brewDir := filepath.Join(env.TempDir, "opt", "homebrew", "Cellar", "rustup", "1.28.0", "bin")
		env.Environ["PATH"] = brewDir

		rustupPath := filepath.Join(brewDir, "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		if len(findings) == 0 {
			t.Fatal("expected at least one finding")
		}

		// Check guidance mentions brew
		f := findings[0]
		if !strings.Contains(f.GuidanceCompact, "brew upgrade rustup") {
			t.Errorf("expected brew guidance, got %s", f.GuidanceCompact)
		}
	})
}

// TestRustupFix tests the fix functionality.
// Ports scenarios from legacy/tests/test_fix_rustup.sh.
func TestRustupFix(t *testing.T) {
	t.Run("official install answer y", func(t *testing.T) {
		// Scenario 1: official rustup-init install, answer y -> Changed
		env := testutil.NewTestEnvT(t)

		version := "1.28.0"
		callCount := 0

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			callCount++
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				// First call (audit): returns old version
				// Second+ calls (after update): returns new version
				if callCount > 2 {
					version = "1.29.2"
				}
				return exec.CommandResult{Stdout: "rustup " + version + " (abc123 2026-01-01)"}
			}
			if isRustupCmd(name) && len(args) >= 2 && args[0] == "self" && args[1] == "update" {
				// Simulate self update
				version = "1.29.2"
				return exec.CommandResult{Stdout: "rustup updated"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["HOME"] = env.TempDir
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

		k := New()
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		// Plan fixes
		fixer := k.(kinds.Fixer)
		fixes, err := fixer.Plan(context.Background(), env, findings)
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}

		if len(fixes) != 1 {
			t.Fatalf("expected 1 fix, got %d", len(fixes))
		}

		// Run the fix with fake privilege escalator that allows writes
		var out bytes.Buffer
		fakePriv := privilege.NewFakeEscalator()
		fakePriv.IsRootVal = true // Pretend we're root so no need for sudo
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
		if !strings.Contains(output, "1.29.2") {
			t.Errorf("expected output to mention new version 1.29.2, got:\n%s", output)
		}
		if !strings.Contains(output, "version check, not a TLS probe") {
			t.Errorf("expected 'version check, not a TLS probe' in output, got:\n%s", output)
		}
	})

	t.Run("decline", func(t *testing.T) {
		// Scenario 2: answer n -> Skipped
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["HOME"] = env.TempDir
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["HOME"] = env.TempDir
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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

	t.Run("homebrew install", func(t *testing.T) {
		// Scenario 4: Homebrew install never runs self update
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		// Use a Homebrew-style path
		brewDir := filepath.Join(env.TempDir, "opt", "homebrew", "Cellar", "rustup", "1.28.0", "bin")
		env.Environ["PATH"] = brewDir

		rustupPath := filepath.Join(brewDir, "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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

		// No fixes should be scheduled for Homebrew install
		if len(fixes) != 0 {
			t.Errorf("expected 0 fixes for Homebrew install, got %d", len(fixes))
		}
	})

	t.Run("cargo home override", func(t *testing.T) {
		// Scenario 5: CARGO_HOME override is honored
		env := testutil.NewTestEnvT(t)

		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "rustup 1.29.2 (abc123 2026-01-01)"}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		customHome := filepath.Join(env.TempDir, "custom-cargo")
		env.Environ["CARGO_HOME"] = customHome
		env.Environ["PATH"] = filepath.Join(customHome, "bin")

		rustupPath := filepath.Join(customHome, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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

		// Should be 0 fixes since version is already OK
		if len(fixes) != 0 {
			t.Errorf("expected 0 fixes for already-fixed version, got %d", len(fixes))
		}
	})

	t.Run("update that does nothing", func(t *testing.T) {
		// Scenario 6: update that does nothing leaves binary working
		env := testutil.NewTestEnvT(t)

		version := "1.28.0"
		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				// Version stays the same
				return exec.CommandResult{Stdout: "rustup " + version + " (abc123 2026-01-01)"}
			}
			if isRustupCmd(name) && len(args) >= 2 && args[0] == "self" && args[1] == "update" {
				// Update does nothing
				return exec.CommandResult{Stdout: "info: checking for self-updates"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["HOME"] = env.TempDir
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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
	})

	t.Run("update that breaks the binary", func(t *testing.T) {
		// Scenario 7: update that breaks the binary is rolled back
		env := testutil.NewTestEnvT(t)

		calls := 0
		runner := exec.NewFakeRunner()
		runner.OnCall = func(name string, args ...string) exec.CommandResult {
			calls++
			if isRustupCmd(name) && len(args) > 0 && args[0] == "--version" {
				// First call (audit) returns OK, subsequent calls (after break) fail
				if calls > 2 {
					return exec.CommandResult{ExitCode: 1, Error: fmt.Errorf("broken binary")}
				}
				return exec.CommandResult{Stdout: "rustup 1.28.0 (abc123 2026-01-01)"}
			}
			if isRustupCmd(name) && len(args) >= 2 && args[0] == "self" && args[1] == "update" {
				// Update breaks the binary
				return exec.CommandResult{Stdout: "rustup updated"}
			}
			if name == "cp" {
				return exec.CommandResult{}
			}
			return exec.CommandResult{}
		}
		env.Run = runner

		env.Environ["HOME"] = env.TempDir
		env.Environ["CARGO_HOME"] = env.TempDir
		env.Environ["PATH"] = filepath.Join(env.TempDir, "bin")

		rustupPath := filepath.Join(env.TempDir, "bin", "rustup")
		if err := os.MkdirAll(filepath.Dir(rustupPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustupPath, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatal(err)
		}

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
		// back. A restore is a cp -p of the backup over the original.
		wantRestore := "cp -p " + rustupPath + ".pre-emudhra-20260101120000 " + rustupPath
		restored := false
		for _, c := range fakePriv.Commands {
			if c == wantRestore {
				restored = true
			}
		}
		if !restored {
			t.Errorf("the previous binary was not restored; expected %q among %q", wantRestore, fakePriv.Commands)
		}
	})
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
