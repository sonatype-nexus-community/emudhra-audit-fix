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

package golang

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	assert.Equal(t, "golang", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Go installations", k.Describe())
}

func TestKind_Applicable(t *testing.T) {
	k := New()
	assert.True(t, k.Applicable(platform.Host{OS: "darwin"}).Applies)
	assert.True(t, k.Applicable(platform.Host{OS: "linux"}).Applies)
}

// TestKind_StatusDerivation tests that the Kind properly uses SetProbe/SetVersion
// and lets Finding.Status() derive the correct status
func TestKind_StatusDerivation(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		probeResult kinds.ProbeResult
		offline     bool
		wantStatus  kinds.Status
		wantCheck   kinds.VersionCheck
	}{
		{
			name:        "probe trusted - AFFECTED",
			version:     "1.27.3",
			probeResult: kinds.ProbeTrusted,
			wantStatus:  kinds.StatusAffected,
			wantCheck:   kinds.VersionOK,
		},
		{
			name:        "probe rejected - OK",
			version:     "1.27.0",
			probeResult: kinds.ProbeRejected,
			wantStatus:  kinds.StatusOK,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "inconclusive + behind - LIKELY-AFFECTED",
			version:     "1.27.0",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusLikelyAffected,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "inconclusive + OK - LIKELY-OK",
			version:     "1.27.3",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusLikelyOK,
			wantCheck:   kinds.VersionOK,
		},
		{
			name:        "inconclusive + nofix - LIKELY-AFFECTED",
			version:     "1.25.0",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusLikelyAffected,
			wantCheck:   kinds.VersionNoFix,
		},
		{
			name:        "offline + behind - LIKELY-AFFECTED",
			version:     "1.27.0",
			probeResult: kinds.ProbeSkipped,
			offline:     true,
			wantStatus:  kinds.StatusLikelyAffected,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "offline + fixed - LIKELY-OK",
			version:     "1.27.3",
			probeResult: kinds.ProbeSkipped,
			offline:     true,
			wantStatus:  kinds.StatusLikelyOK,
			wantCheck:   kinds.VersionOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnv()

			// Create temp dir and fake go binary
			tmpDir := t.TempDir()
			goPath := filepath.Join(tmpDir, "go")
			require.NoError(t, os.WriteFile(goPath, []byte("#!/bin/sh\necho fake"), 0755))

			// Use filepath.EvalSymlinks to get the real path (handles macOS /private/var)
			realTmpDir, err := filepath.EvalSymlinks(tmpDir)
			require.NoError(t, err)

			// Set up fake runner
			runner := env.Run.(*exec.FakeRunner)
			runner.OnCall = func(name string, args ...string) exec.CommandResult {
				if strings.HasSuffix(name, "go") {
					if len(args) > 0 && args[0] == "version" {
						return exec.CommandResult{
							Stdout: "go version go" + tt.version + " darwin/arm64\n",
						}
					}
					if len(args) > 1 && args[0] == "run" && !tt.offline {
						return exec.CommandResult{
							Stdout: buildProbeOutput(tt.probeResult),
						}
					}
				}
				return exec.CommandResult{}
			}

			env.Environ["PATH"] = tmpDir
			env.Environ["HOME"] = tmpDir
			env.Offline = tt.offline
			env.TempDir = t.TempDir()

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)

			// Find our test finding (not system go)
			var f *kinds.Finding
			for i := range findings {
				if strings.HasPrefix(findings[i].Path, realTmpDir) || strings.HasPrefix(findings[i].Path, tmpDir) {
					f = &findings[i]
					break
				}
			}
			require.NotNil(t, f, "should find our test go binary")

			assert.Equal(t, tt.wantCheck, f.VersionCheck, "version check")
			assert.Equal(t, tt.wantStatus, f.Status(), "status")
		})
	}
}

func TestKind_Guidance(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpDir := t.TempDir()
	goPath := filepath.Join(tmpDir, "go")
	require.NoError(t, os.WriteFile(goPath, []byte("#!/bin/sh\necho fake"), 0755))

	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	runner := env.Run.(*exec.FakeRunner)
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if strings.HasSuffix(name, "go") {
			if len(args) > 0 && args[0] == "version" {
				return exec.CommandResult{Stdout: "go version go1.27.0 darwin/arm64\n"}
			}
			if len(args) > 1 && args[0] == "run" {
				return exec.CommandResult{Stdout: buildProbeOutput(kinds.ProbeTrusted)}
			}
		}
		return exec.CommandResult{}
	}

	env.Environ["PATH"] = tmpDir
	env.Environ["HOME"] = tmpDir
	env.TempDir = t.TempDir()

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	var f *kinds.Finding
	for i := range findings {
		if strings.HasPrefix(findings[i].Path, realTmpDir) || strings.HasPrefix(findings[i].Path, tmpDir) {
			f = &findings[i]
			break
		}
	}
	require.NotNil(t, f)
	assert.Contains(t, f.GuidanceCompact, "upgrade Go to")
}

func TestKind_Audit_Hermetic(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Environ["HOME"] = "/nonexistent"
	env.Environ["PATH"] = "/nonexistent"

	// Should not crash even with garbage HOME/PATH
	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
	// May or may not find system Go, but should not panic
	for _, f := range findings {
		assert.NotPanics(t, func() { _ = f.Status() })
	}
}

func buildProbeOutput(result kinds.ProbeResult) string {
	switch result {
	case kinds.ProbeTrusted:
		return "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n"
	case kinds.ProbeRejected:
		return "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n"
	default:
		return "err https://github.com/\n"
	}
}

// The report shows a Go where it was found, not where its symlink leads (the script's report "Go" "$g").
func TestAuditReportsThePathAsFoundNotTheResolvedOne(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	real := filepath.Join(root, "Cellar", "go", "libexec", "bin")
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.MkdirAll(real, 0o755))
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(real, "go"), []byte("#!/bin/sh\necho go version go1.26.4 darwin/arm64\n"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(real, "go"), filepath.Join(bin, "go")))
	env := testutil.NewTestEnvT(t)
	env.Run = exec.NewRealRunner()
	env.Offline = true
	env.Environ = map[string]string{"HOME": filepath.Join(root, "home"), "PATH": bin}

	fs, err := New().Audit(context.Background(), env)
	require.NoError(t, err)

	var f *kinds.Finding
	for i := range fs { // the Kind also looks in the fixed host locations
		if strings.HasPrefix(fs[i].Path, root) {
			f = &fs[i]
		}
	}
	require.NotNil(t, f)
	assert.Equal(t, filepath.Join(bin, "go"), f.Path)
	assert.Equal(t, "upgrade Go to 1.26.10 or later (https://go.dev/dl/)", f.GuidanceCompact)
	for _, l := range f.GuidanceFull {
		assert.NotEqual(t, "Upgrade Go to 1.26.10 or later (https://go.dev/dl/)", l, "the script's full guidance has only the source-specific line")
	}
}
