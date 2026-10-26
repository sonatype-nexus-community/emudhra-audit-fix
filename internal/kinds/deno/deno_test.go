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

package deno

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
	assert.Equal(t, "deno", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Deno installations", k.Describe())
}

func TestKind_Applicable(t *testing.T) {
	k := New()
	assert.True(t, k.Applicable(platform.Host{OS: "darwin"}).Applies)
	assert.True(t, k.Applicable(platform.Host{OS: "linux"}).Applies)
}

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
			version:     "2.9.8",
			probeResult: kinds.ProbeTrusted,
			wantStatus:  kinds.StatusAffected,
			wantCheck:   kinds.VersionOK,
		},
		{
			name:        "probe rejected - OK",
			version:     "2.9.0",
			probeResult: kinds.ProbeRejected,
			wantStatus:  kinds.StatusOK,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "inconclusive + behind - LIKELY-AFFECTED",
			version:     "2.9.0",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusLikelyAffected,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "inconclusive + OK - LIKELY-OK",
			version:     "2.9.8",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusLikelyOK,
			wantCheck:   kinds.VersionOK,
		},
		{
			name:        "offline + behind - LIKELY-AFFECTED",
			version:     "2.9.0",
			probeResult: kinds.ProbeSkipped,
			offline:     true,
			wantStatus:  kinds.StatusLikelyAffected,
			wantCheck:   kinds.VersionBehind,
		},
		{
			name:        "offline + fixed - LIKELY-OK",
			version:     "2.9.8",
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

			tmpDir := t.TempDir()
			denoPath := filepath.Join(tmpDir, "deno")
			require.NoError(t, os.WriteFile(denoPath, []byte("#!/bin/sh\necho fake"), 0755))

			realTmpDir, err := filepath.EvalSymlinks(tmpDir)
			require.NoError(t, err)

			runner := env.Run.(*exec.FakeRunner)
			runner.OnCall = func(name string, args ...string) exec.CommandResult {
				if strings.HasSuffix(name, "deno") {
					if len(args) > 0 && args[0] == "--version" {
						return exec.CommandResult{
							Stdout: "deno " + tt.version + " (stable, release, aarch64-apple-darwin)\nv8 12.7.224.13\ntypescript 5.4.5\n",
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

			findings, err := k.Audit(context.Background(), env)
			require.NoError(t, err)

			var f *kinds.Finding
			for i := range findings {
				if strings.HasPrefix(findings[i].Path, realTmpDir) {
					f = &findings[i]
					break
				}
			}
			require.NotNil(t, f, "should find our test deno binary")

			assert.Equal(t, tt.wantCheck, f.VersionCheck, "version check")
			assert.Equal(t, tt.wantStatus, f.Status(), "status")
		})
	}
}

func TestKind_Guidance_Verbatim(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpDir := t.TempDir()
	denoPath := filepath.Join(tmpDir, "deno")
	require.NoError(t, os.WriteFile(denoPath, []byte("#!/bin/sh\necho fake"), 0755))

	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	runner := env.Run.(*exec.FakeRunner)
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if strings.HasSuffix(name, "deno") {
			if len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{
					Stdout: "deno 2.9.0 (stable, release, aarch64-apple-darwin)\nv8 12.7.224.13\ntypescript 5.4.5\n",
				}
			}
			if len(args) > 1 && args[0] == "run" {
				return exec.CommandResult{
					Stdout: buildProbeOutput(kinds.ProbeTrusted),
				}
			}
		}
		return exec.CommandResult{}
	}

	env.Environ["PATH"] = tmpDir
	env.Environ["HOME"] = tmpDir

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)

	var f *kinds.Finding
	for i := range findings {
		if strings.HasPrefix(findings[i].Path, realTmpDir) {
			f = &findings[i]
			break
		}
	}
	require.NotNil(t, f)

	// Check guidance is verbatim from script
	assert.Contains(t, f.GuidanceFull[0], "Upgrade Deno to 2.9.8 or later: deno upgrade   (or brew upgrade deno)")
}

func TestKind_Audit_Hermetic(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Environ["HOME"] = "/nonexistent"
	env.Environ["PATH"] = "/nonexistent"

	findings, err := k.Audit(context.Background(), env)
	require.NoError(t, err)
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
