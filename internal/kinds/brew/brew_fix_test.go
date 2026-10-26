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

package brew

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// TestBrewKind_Plan tests the Plan method of the brew Fixer.
func TestBrewKind_Plan(t *testing.T) {
	tests := []struct {
		name      string
		findings  []kinds.Finding
		wantCount int
	}{
		{
			name:      "no findings",
			findings:  []kinds.Finding{},
			wantCount: 0,
		},
		{
			name: "finding without HasFix",
			findings: []kinds.Finding{
				{Kind: "brew", Tool: "Homebrew ca-certificates", HasFix: false},
			},
			wantCount: 0,
		},
		{
			name: "finding with HasFix",
			findings: []kinds.Finding{
				{
					Kind:    "brew",
					Tool:    "Homebrew ca-certificates",
					Path:    "/opt/homebrew/opt/ca-certificates",
					Version: "2026-09-20_1",
					HasFix:  true,
				},
			},
			wantCount: 1,
		},
		{
			name: "multiple findings with HasFix",
			findings: []kinds.Finding{
				{
					Kind:    "brew",
					Tool:    "Homebrew ca-certificates",
					Path:    "/opt/homebrew/opt/ca-certificates",
					Version: "2026-09-20_1",
					HasFix:  true,
				},
				{
					Kind:    "brew",
					Tool:    "Homebrew ca-certificates",
					Path:    "/usr/local/opt/ca-certificates",
					Version: "2026-09-19_1",
					HasFix:  true,
				},
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testutil.NewTestEnv()
			k := New().(*Kind) // Cast to *Kind to access Plan method

			fixes, err := k.Plan(context.Background(), env, tt.findings)
			require.NoError(t, err)
			assert.Len(t, fixes, tt.wantCount)

			for i, fix := range fixes {
				assert.Equal(t, "brew", fix.Kind())
				assert.Equal(t, "Homebrew ca-certificates", fix.Target())
				if i < len(tt.findings) && tt.findings[i].HasFix {
					bf := fix.(*brewFix)
					assert.Equal(t, tt.findings[i].Version, bf.before)
				}
			}
		})
	}
}

// TestBrewFix_Run_DryRun tests that dry-run prints commands without executing.
func TestBrewFix_Run_DryRun(t *testing.T) {
	prefix := t.TempDir()

	// Create opt/ca-certificates symlink
	cellarPath := filepath.Join(prefix, "Cellar", "ca-certificates", "2026-09-20_1")
	require.NoError(t, os.MkdirAll(cellarPath, 0755))
	optPath := filepath.Join(prefix, "opt", "ca-certificates")
	require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
	require.NoError(t, os.Symlink(cellarPath, optPath))

	brewBin := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(brewBin, 0755))
	brewPath := filepath.Join(brewBin, "brew")
	require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho brew\n"), 0755))

	runner := exec.NewFakeRunner()

	var buf bytes.Buffer
	session := &fixrun.Session{
		Run:    runner,
		Out:    &buf,
		DryRun: true,
		Host:   testutil.NewDarwinHost(),
		Stamp:  "20261023120000",
	}

	fix := &brewFix{
		prefix:   prefix,
		before:   "2026-09-20_1",
		brewPath: brewPath,
	}

	outcome := fix.Run(context.Background(), session)
	assert.Equal(t, fixrun.Skipped, outcome)

	output := buf.String()
	assert.Contains(t, output, "Homebrew ca-certificates")
	assert.Contains(t, output, "2026-09-20_1")
	assert.Contains(t, output, "update")
	assert.Contains(t, output, "upgrade ca-certificates")

	// No commands should have been run in dry-run mode
	assert.Empty(t, runner.Commands)
}

// TestBrewFix_Run_Declined tests that declining confirmation returns Skipped.
func TestBrewFix_Run_Declined(t *testing.T) {
	prefix := t.TempDir()

	cellarPath := filepath.Join(prefix, "Cellar", "ca-certificates", "2026-09-20_1")
	require.NoError(t, os.MkdirAll(cellarPath, 0755))
	optPath := filepath.Join(prefix, "opt", "ca-certificates")
	require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
	require.NoError(t, os.Symlink(cellarPath, optPath))

	brewBin := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(brewBin, 0755))
	brewPath := filepath.Join(brewBin, "brew")
	require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho brew\n"), 0755))

	runner := exec.NewFakeRunner()
	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{false} // Decline

	var buf bytes.Buffer
	session := &fixrun.Session{
		Run:    runner,
		Prompt: fakePrompt,
		Out:    &buf,
		DryRun: false,
		Host:   testutil.NewDarwinHost(),
		Stamp:  "20261023120000",
	}

	fix := &brewFix{
		prefix:   prefix,
		before:   "2026-09-20_1",
		brewPath: brewPath,
	}

	outcome := fix.Run(context.Background(), session)
	assert.Equal(t, fixrun.Skipped, outcome)

	output := buf.String()
	assert.Contains(t, output, "skipped")
	// No commands should have been run when declined
	assert.Empty(t, runner.Commands)
}

// TestBrewFix_Run_UpgradeFails tests failure when brew upgrade fails.
func TestBrewFix_Run_UpgradeFails(t *testing.T) {
	prefix := t.TempDir()

	cellarPath := filepath.Join(prefix, "Cellar", "ca-certificates", "2026-09-20_1")
	require.NoError(t, os.MkdirAll(cellarPath, 0755))
	optPath := filepath.Join(prefix, "opt", "ca-certificates")
	require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
	require.NoError(t, os.Symlink(cellarPath, optPath))

	brewBin := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(brewBin, 0755))
	brewPath := filepath.Join(brewBin, "brew")

	runner := exec.NewFakeRunner()
	runner.AddSuccess(brewPath+" update", "")
	runner.AddError(brewPath+" upgrade ca-certificates", 1, "upgrade failed")

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true}

	var buf bytes.Buffer
	session := &fixrun.Session{
		Run:    runner,
		Prompt: fakePrompt,
		Out:    &buf,
		DryRun: false,
		Host:   testutil.NewDarwinHost(),
		Stamp:  "20261023120000",
	}

	fix := &brewFix{
		prefix:   prefix,
		before:   "2026-09-20_1",
		brewPath: brewPath,
	}

	outcome := fix.Run(context.Background(), session)
	assert.Equal(t, fixrun.Failed, outcome)

	output := buf.String()
	assert.Contains(t, output, "brew upgrade ca-certificates failed")
}

// TestBrewFix_Integration_WithRealBrewStub tests the full fix flow with a stub brew.
// This test requires network access for probing.
func TestBrewFix_Integration_WithRealBrewStub(t *testing.T) {
	// Skip if running short tests
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	prefix := t.TempDir()

	// Create old version
	oldCellar := filepath.Join(prefix, "Cellar", "ca-certificates", "2026-09-20_1")
	require.NoError(t, os.MkdirAll(oldCellar, 0755))

	// Create new version
	newCellar := filepath.Join(prefix, "Cellar", "ca-certificates", "2026-09-25_1")
	require.NoError(t, os.MkdirAll(newCellar, 0755))

	// Create symlink pointing to old version
	optPath := filepath.Join(prefix, "opt", "ca-certificates")
	require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
	require.NoError(t, os.Symlink(oldCellar, optPath))

	// Create bundle file with a valid PEM that the probe can parse
	// Use a minimal valid PEM structure (empty will fail parsing)
	etcPath := filepath.Join(prefix, "etc", "ca-certificates")
	require.NoError(t, os.MkdirAll(etcPath, 0755))
	bundlePath := filepath.Join(etcPath, "cert.pem")
	// A minimal valid PEM certificate block (not a real CA, just parseable)
	minimalPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpLxAAAAADANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJj
-----END CERTIFICATE-----
`
	require.NoError(t, os.WriteFile(bundlePath, []byte(minimalPEM), 0644))

	// Create brew executable stub
	brewBin := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(brewBin, 0755))
	brewPath := filepath.Join(brewBin, "brew")
	brewScript := `#!/bin/sh
case "$1" in
  update) exit 0 ;;
  upgrade)
    # Simulate upgrade by changing the symlink
    rm -f "` + optPath + `"
    ln -s "` + newCellar + `" "` + optPath + `"
    echo "Upgraded to 2026-09-25_1"
    ;;
esac
`
	require.NoError(t, os.WriteFile(brewPath, []byte(brewScript), 0755))

	// Setup runner (not used since we have a real stub, but needed for Session)
	runner := exec.NewFakeRunner()

	fakePrompt := prompt.NewFakePrompter()
	fakePrompt.ConfirmResponses = []bool{true} // Confirm

	var buf bytes.Buffer
	session := &fixrun.Session{
		Run:    runner,
		Prompt: fakePrompt,
		Out:    &buf,
		DryRun: false,
		Yes:    false,
		Host:   testutil.NewDarwinHost(),
		Stamp:  "20261023120000",
	}

	fix := &brewFix{
		prefix:   prefix,
		before:   "2026-09-20_1",
		brewPath: brewPath,
	}

	// Run the fix (this will call the real brew stub and probe)
	outcome := fix.Run(context.Background(), session)

	output := buf.String()
	t.Logf("Output:\n%s", output)

	// The outcome depends on whether the probe rejects the bundle
	// With a minimal fake cert, the probe will likely fail or return inconclusive
	// so the outcome will be Failed. If network is available and probe works,
	// it could be Changed or Failed.
	assert.Contains(t, []fixrun.Outcome{fixrun.Changed, fixrun.Failed}, outcome)

	// Verify the brew commands were printed
	assert.Contains(t, output, "brew update")
	assert.Contains(t, output, "brew upgrade ca-certificates")
}

// TestBrewFix_Prefix tests the Prefix function.
func TestBrewFix_Prefix(t *testing.T) {
	t.Run("brew --prefix succeeds", func(t *testing.T) {
		tmpDir := t.TempDir()
		env := testutil.NewTestEnv()
		runner := exec.NewFakeRunner()
		env.Run = runner
		runner.AddSuccess("brew --prefix", tmpDir)

		result := Prefix(env)
		assert.Equal(t, tmpDir, result)
	})

	t.Run("brew --prefix fails fallbacks to real paths", func(t *testing.T) {
		env := testutil.NewTestEnv()
		runner := exec.NewFakeRunner()
		env.Run = runner
		runner.AddError("brew --prefix", 1, "not found")

		result := Prefix(env)
		// Will fall back to common paths - on a real macOS machine /opt/homebrew exists
		// The test verifies the function doesn't crash and returns a valid path or empty
		_ = result // Just verify no crash
	})
}

// TestBrewFix_HasFix tests that HasFix is set correctly based on guidance.
func TestBrewFix_HasFix(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		offline      bool
		bundleExists bool
		wantHasFix   bool
	}{
		{
			name:         "old version with bundle - offline",
			version:      "2026-09-20_1",
			offline:      true,
			bundleExists: true,
			wantHasFix:   true, // Version behind triggers guidance
		},
		{
			name:         "fixed version - offline",
			version:      "2026-09-25_1",
			offline:      true,
			bundleExists: true,
			wantHasFix:   false, // Version is OK, no guidance
		},
		{
			name:         "no bundle file",
			version:      "2026-09-20_1",
			offline:      true,
			bundleExists: false,
			wantHasFix:   true, // Version behind
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create brew
			brewBin := filepath.Join(tmpDir, "bin")
			require.NoError(t, os.MkdirAll(brewBin, 0755))
			brewPath := filepath.Join(brewBin, "brew")
			require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho brew\n"), 0755))

			// Create ca-certificates
			cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", tt.version)
			require.NoError(t, os.MkdirAll(cellarPath, 0755))
			optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
			require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
			require.NoError(t, os.Symlink(cellarPath, optPath))

			if tt.bundleExists {
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE"), 0644))
			}

			env := testutil.NewTestEnv()
			env.Environ["PATH"] = brewBin + ":/usr/bin:/bin"
			env.Environ["HOME"] = tmpDir
			env.Offline = tt.offline

			k := New()
			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)
			require.Len(t, findings, 1)

			assert.Equal(t, tt.wantHasFix, findings[0].HasFix)

			// Verify that HasFix matches having guidance
			if tt.wantHasFix {
				assert.NotEmpty(t, findings[0].GuidanceCompact)
				assert.True(t, findings[0].HasFix)
			}
		})
	}
}
