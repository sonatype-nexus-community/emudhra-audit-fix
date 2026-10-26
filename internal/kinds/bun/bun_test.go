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

package bun

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
	assert.Equal(t, "bun", k.ID())
}

func TestKind_Describe(t *testing.T) {
	k := New()
	assert.Equal(t, "Bun installations", k.Describe())
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
	}{
		{
			name:        "probe trusted - AFFECTED (no fixed version)",
			version:     "1.0.0",
			probeResult: kinds.ProbeTrusted,
			wantStatus:  kinds.StatusAffected,
		},
		{
			name:        "probe rejected - OK",
			version:     "1.0.0",
			probeResult: kinds.ProbeRejected,
			wantStatus:  kinds.StatusOK,
		},
		{
			name:        "inconclusive - UNKNOWN",
			version:     "1.0.0",
			probeResult: kinds.ProbeInconclusive,
			wantStatus:  kinds.StatusUnknown,
		},
		{
			name:        "offline - UNKNOWN",
			version:     "1.0.0",
			probeResult: kinds.ProbeSkipped,
			offline:     true,
			wantStatus:  kinds.StatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnv()

			tmpDir := t.TempDir()
			bunPath := filepath.Join(tmpDir, "bun")
			require.NoError(t, os.WriteFile(bunPath, []byte("#!/bin/sh\necho fake"), 0755))

			realTmpDir, err := filepath.EvalSymlinks(tmpDir)
			require.NoError(t, err)

			runner := env.Run.(*exec.FakeRunner)
			runner.OnCall = func(name string, args ...string) exec.CommandResult {
				if strings.HasSuffix(name, "bun") {
					if len(args) > 0 && args[0] == "--version" {
						return exec.CommandResult{Stdout: tt.version + "\n"}
					}
					if len(args) > 1 && args[0] == "run" && !tt.offline {
						return exec.CommandResult{Stdout: buildProbeOutput(tt.probeResult)}
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
			require.NotNil(t, f, "should find our test bun binary")

			assert.Equal(t, tt.wantStatus, f.Status(), "status")
			// Bun has no fixed version, so VersionCheck should be na
			assert.Equal(t, kinds.VersionNA, f.VersionCheck, "version check should be na for bun")
		})
	}
}

func TestKind_Guidance_Verbatim(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpDir := t.TempDir()
	bunPath := filepath.Join(tmpDir, "bun")
	require.NoError(t, os.WriteFile(bunPath, []byte("#!/bin/sh\necho fake"), 0755))

	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	runner := env.Run.(*exec.FakeRunner)
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if strings.HasSuffix(name, "bun") {
			if len(args) > 0 && args[0] == "--version" {
				return exec.CommandResult{Stdout: "1.0.0\n"}
			}
			if len(args) > 1 && args[0] == "run" {
				return exec.CommandResult{Stdout: buildProbeOutput(kinds.ProbeTrusted)}
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
	assert.Contains(t, f.GuidanceFull[0], "The page lists no fixed Bun release yet (pending). Watch https://emudhra.we-have-a-problem.com/")
	assert.Contains(t, f.GuidanceFull[1], "and upgrade as soon as one ships: bun upgrade. Until then avoid Bun for sensitive outbound TLS.")
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
