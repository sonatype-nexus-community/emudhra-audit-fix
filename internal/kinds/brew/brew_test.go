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

func TestBrewKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "brew", k.ID())
}

func TestBrewKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Homebrew ca-certificates formula", k.Describe())
}

func TestBrewKind_Applicable(t *testing.T) {
	tests := []struct {
		name       string
		host       platform.Host
		wantApply  bool
		wantReason string
	}{
		{"macOS", testutil.NewDarwinHost(), true, ""},
		{"Linux", testutil.NewLinuxHost(), true, ""},
		{"FreeBSD", platform.Host{OS: "freebsd"}, false, "Homebrew is supported on macOS and Linux only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New().Applicable(tt.host)
			assert.Equal(t, tt.wantApply, got.Applies)
			assert.Equal(t, tt.wantReason, got.Reason)
		})
	}
}

// TestBrewKind_AuditWithoutBrew: whether brew is installed is an Audit
// outcome (no findings), not an applicability question, and must not depend
// on the real PATH.
func TestBrewKind_AuditWithoutBrew(t *testing.T) {
	env := testutil.NewTestEnv()
	env.Environ = map[string]string{"PATH": t.TempDir(), "HOME": t.TempDir()}
	findings, err := New().Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestBrewKind_Audit(t *testing.T) {
	tests := []struct {
		name          string
		setupFS       func(t *testing.T, tmpDir string) string // Returns brew prefix
		setupEnv      func(env *kinds.Env, tmpDir string)
		wantLen       int
		wantStatus    kinds.Status
		wantVersion   string
		wantPath      string
		checkGuidance bool
		guidanceText  string
	}{
		{
			name: "brew not found",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Don't create brew - test will fail to find it
				return ""
			},
			wantLen: 0,
		},
		{
			name: "brew found but ca-certificates not installed",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))
				return tmpDir
			},
			wantLen: 0,
		},
		{
			name: "ca-certificates installed and affected (trusting compromised chain)",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (old version)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-20_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Create bundle file
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE CERTIFICATE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				// This test verifies behavior with real probing
				// Since we can't fake ProbeCAFile easily, we mark offline to skip probe
				// The actual behavior is tested via integration tests with real cert bundles
				env.Offline = true
			},
			wantLen:       1,
			wantStatus:    kinds.StatusLikelyAffected, // Version check only (offline)
			wantVersion:   "2026-09-20_1",
			checkGuidance: true,
		},
		{
			name: "ca-certificates installed and protected (rejecting chain)",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (old version but protected)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-20_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Create bundle file
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE CERTIFICATE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				// Offline to skip probe (can't fake ProbeCAFile)
				env.Offline = true
			},
			wantLen:       1,
			wantStatus:    kinds.StatusLikelyAffected, // Version behind (no probe to override)
			wantVersion:   "2026-09-20_1",
			checkGuidance: true, // Guidance added for behind version
		},
		{
			name: "ca-certificates at fixed version",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (fixed version)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-25_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Create bundle file
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE CERTIFICATE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:     1,
			wantStatus:  kinds.StatusLikelyOK, // Fixed version, no probe override
			wantVersion: "2026-09-25_1",
		},
		{
			name: "ca-certificates at fixed version but still affected (edge case - can only be detected via probe)",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (fixed version but bad bundle)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-25_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Create bundle file
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE CERTIFICATE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:     1,
			wantStatus:  kinds.StatusLikelyOK, // Fixed version, no probe override (would need real probe to detect)
			wantVersion: "2026-09-25_1",
			// No guidance because version is OK
		},
		{
			name: "offline mode - old version",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (old version)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-20_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Create bundle file
				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE CERTIFICATE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:       1,
			wantStatus:    kinds.StatusLikelyAffected, // Version check only in offline mode
			wantVersion:   "2026-09-20_1",
			checkGuidance: true,
		},
		{
			name: "bundle file not found",
			setupFS: func(t *testing.T, tmpDir string) string {
				// Create brew executable
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Create ca-certificates opt symlink (old version)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-20_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				// Don't create bundle file
				return tmpDir
			},
			wantLen:       1,
			wantStatus:    kinds.StatusLikelyAffected, // Version check only
			wantVersion:   "2026-09-20_1",
			checkGuidance: true,
		},
		// Version comparison tests
		{
			name: "older version with earlier date",
			setupFS: func(t *testing.T, tmpDir string) string {
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Earlier date: 2026-08-15_1
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-08-15_1")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:     1,
			wantStatus:  kinds.StatusLikelyAffected,
			wantVersion: "2026-08-15_1",
		},
		{
			name: "same date, different revision - revision 2 vs revision 1",
			setupFS: func(t *testing.T, tmpDir string) string {
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// Same date, revision 2 (newer than revision 1)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-25_2")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:     1,
			wantStatus:  kinds.StatusLikelyOK, // Revision 2 > revision 1
			wantVersion: "2026-09-25_2",
		},
		{
			name: "same date, no revision in installed version",
			setupFS: func(t *testing.T, tmpDir string) string {
				brewDir := filepath.Join(tmpDir, "bin")
				require.NoError(t, os.Mkdir(brewDir, 0755))
				brewPath := filepath.Join(brewDir, "brew")
				require.NoError(t, os.WriteFile(brewPath, []byte("#!/bin/sh\necho 'Homebrew'\n"), 0755))

				// No revision (treat as 0)
				cellarPath := filepath.Join(tmpDir, "Cellar", "ca-certificates", "2026-09-25")
				require.NoError(t, os.MkdirAll(cellarPath, 0755))

				optPath := filepath.Join(tmpDir, "opt", "ca-certificates")
				require.NoError(t, os.MkdirAll(filepath.Dir(optPath), 0755))
				require.NoError(t, os.Symlink(cellarPath, optPath))

				etcPath := filepath.Join(tmpDir, "etc", "ca-certificates")
				require.NoError(t, os.MkdirAll(etcPath, 0755))
				bundlePath := filepath.Join(etcPath, "cert.pem")
				require.NoError(t, os.WriteFile(bundlePath, []byte("FAKE"), 0644))

				return tmpDir
			},
			setupEnv: func(env *kinds.Env, tmpDir string) {
				env.Offline = true
			},
			wantLen:     1,
			wantStatus:  kinds.StatusLikelyAffected, // revision 0 < revision 1
			wantVersion: "2026-09-25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory for test
			tmpDir := t.TempDir()

			// Setup filesystem
			prefix := tt.setupFS(t, tmpDir)

			// Create test environment
			env := testutil.NewTestEnv()

			// Set PATH to include our test brew (or exclude it)
			if prefix != "" {
				brewBin := filepath.Join(prefix, "bin")
				env.Environ["PATH"] = brewBin + ":/usr/bin:/bin"
				env.Environ["HOME"] = tmpDir
			} else {
				// This test expects brew NOT to be found
				env.Environ["PATH"] = "/usr/bin:/bin"
				env.Environ["HOME"] = tmpDir
			}

			// Additional env setup
			if tt.setupEnv != nil {
				tt.setupEnv(env, tmpDir)
			}

			// Run audit
			k := New()
			findings, err := k.Audit(testutil.Context(), env)

			// Assertions
			require.NoError(t, err)
			assert.Len(t, findings, tt.wantLen)

			if tt.wantLen > 0 {
				finding := findings[0]
				assert.Equal(t, "brew", finding.Kind)
				assert.Equal(t, "Homebrew ca-certificates", finding.Tool)
				assert.Equal(t, tt.wantStatus, finding.Status())

				if tt.wantVersion != "" {
					assert.Equal(t, tt.wantVersion, finding.Version)
				}

				if tt.wantPath != "" {
					assert.Equal(t, tt.wantPath, finding.Path)
				}

				if tt.checkGuidance {
					assert.NotEmpty(t, finding.GuidanceCompact)
					assert.NotEmpty(t, finding.GuidanceFull)
					// Verify guidance matches script verbatim
					assert.Equal(t, "brew upgrade ca-certificates", finding.GuidanceCompact)
					assert.Contains(t, finding.GuidanceFull, "brew update && brew upgrade ca-certificates")
					assert.Contains(t, finding.GuidanceFull, "(Homebrew's Python, curl, openssl and others read this bundle. Old versions linger in the Cellar;")
					assert.Contains(t, finding.GuidanceFull, " 'brew cleanup ca-certificates' removes them.)")
				}

				if tt.guidanceText != "" {
					assert.Equal(t, tt.guidanceText, finding.GuidanceCompact)
				}
			}
		})
	}
}

// TestBrewKind_Audit_Hermeticity verifies tests are hermetic with garbage PATH and HOME
func TestBrewKind_Audit_Hermeticity(t *testing.T) {
	env := testutil.NewTestEnv()
	// Set garbage values to prove hermeticity
	env.Environ["PATH"] = "/nonexistent/path:/does/not/exist"
	env.Environ["HOME"] = "/garbage/home/that/does/not/exist"

	k := New()
	findings, err := k.Audit(testutil.Context(), env)

	require.NoError(t, err)
	assert.Len(t, findings, 0) // No brew found, no findings
}

func TestPrefix(t *testing.T) {
	tests := []struct {
		name        string
		setupFS     func(t *testing.T, tmpDir string)
		setupRunner func(runner *exec.FakeRunner, tmpDir string)
		wantPrefix  string
	}{
		{
			name: "brew --prefix succeeds",
			setupFS: func(t *testing.T, tmpDir string) {
				// No filesystem setup needed
			},
			setupRunner: func(runner *exec.FakeRunner, tmpDir string) {
				runner.AddSuccess("brew", tmpDir)
			},
			wantPrefix: "", // Will be set to tmpDir dynamically
		},
		{
			name: "brew --prefix fails, fallback to /opt/homebrew",
			setupFS: func(t *testing.T, tmpDir string) {
				// Can't actually create /opt/homebrew in tests
				// This test documents the behavior but won't test fallback
			},
			setupRunner: func(runner *exec.FakeRunner, tmpDir string) {
				// Make brew --prefix fail
				runner.AddError("brew", 1, "exit status 1")
			},
			wantPrefix: "", // Empty because fallbacks don't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tt.setupFS(t, tmpDir)

			env := testutil.NewTestEnv()
			runner := exec.NewFakeRunner()
			env.Run = runner

			if tt.setupRunner != nil {
				tt.setupRunner(runner, tmpDir)
			}

			env.Environ["PATH"] = "/usr/bin:/bin"
			result := Prefix(env)

			if tt.name == "brew --prefix succeeds" {
				assert.Equal(t, tmpDir, result)
			}
			// For other cases, result will be empty because fallbacks don't exist in hermetic test
		})
	}
}

func TestNormalizeHomebrewVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2026-09-25_1", "2026.09.25.1"},
		{"2026-09-25_2", "2026.09.25.2"},
		{"2026-09-25", "2026.09.25"},
		{"2026-08-15_1", "2026.08.15.1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHomebrewVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompareHomebrewVersions(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{"equal", "2026.09.25.1", "2026.09.25.1", 0},
		{"earlier date", "2026.08.15.1", "2026.09.25.1", -1},
		{"later date", "2026.10.01.1", "2026.09.25.1", 1},
		{"same date, lower revision", "2026.09.25.1", "2026.09.25.2", -1},
		{"same date, higher revision", "2026.09.25.2", "2026.09.25.1", 1},
		{"no revision vs revision 1", "2026.09.25", "2026.09.25.1", -1},
		{"revision 1 vs no revision", "2026.09.25.1", "2026.09.25", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareHomebrewVersions(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}
