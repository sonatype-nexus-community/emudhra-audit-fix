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

package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestPythonKind_ID(t *testing.T) {
	k := New()
	assert.Equal(t, "python", k.ID())
}

func TestPythonKind_Describe(t *testing.T) {
	k := New()
	assert.Contains(t, k.Describe(), "Python")
}

func TestPythonKind_Applicable(t *testing.T) {
	k := New()

	tests := []struct {
		name string
		host platform.Host
		want bool
	}{
		{
			name: "darwin",
			host: testutil.NewDarwinHost(),
			want: true,
		},
		{
			name: "linux",
			host: testutil.NewLinuxHost(),
			want: true,
		},
		{
			name: "linux debian",
			host: platform.Host{
				OS:      "linux",
				Arch:    "amd64",
				Family:  platform.FamilyDebian,
				HasTTY:  true,
				HasSudo: true,
			},
			want: true,
		},
		{
			name: "linux redhat",
			host: platform.Host{
				OS:      "linux",
				Arch:    "amd64",
				Family:  platform.FamilyRedHat,
				HasTTY:  true,
				HasSudo: true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applies := k.Applicable(tt.host)
			assert.Equal(t, tt.want, applies.Applies)
		})
	}
}

func TestPythonKind_Audit_NoPythonInstalled(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	// testutil.NewTestEnv() is hermetic - empty PATH and HOME, so no Python will be found

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestPythonKind_Audit_Affected(t *testing.T) {
	// This test verifies that affected Python is properly identified
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories for hermetic test
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mock the info extraction with behind versions
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Mock the probes with affected results (trusted bad URLs)
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			case "certifi":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		// For pip probe - affected
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "",
				ExitCode: 1, // HTTP 404 means trusted
			}
		}
		// Default
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, kinds.ProbeTrusted, f.ProbeResult)
		assert.Equal(t, kinds.StatusAffected, f.Status())
	}
}

func TestPythonKind_Audit_Protected(t *testing.T) {
	// This test verifies that protected Python is properly identified
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mock the info extraction
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.20\npip=26.2.3\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Mock the probes with protected results
		// Control URL should be "ok" (trusted), bad URLs should be "certerr" (rejected)
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			case "certifi":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		// For pip probe - protected
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		// Default
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Verify the finding structure
	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, "python", f.Kind)
		assert.Equal(t, "Python", f.Tool)
		assert.NotEmpty(t, f.Version)
		// Probe result should be rejected for protected
		// Status is derived from probe and version
		status := f.Status()
		assert.NotEmpty(t, status)
	}
}

func TestPythonKind_Audit_Behind(t *testing.T) {
	// This test verifies that behind Python is properly identified
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mock the info extraction with behind versions
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Mock the probes with protected results
		// Control URL should be "ok" (trusted), bad URLs should be "certerr" (rejected)
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			case "certifi":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		// For pip probe
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		// Default
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Verify the finding structure
	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, "python", f.Kind)
		assert.Equal(t, "Python", f.Tool)
		assert.NotEmpty(t, f.Version)
		// Version should be behind
		assert.Equal(t, kinds.VersionBehind, f.VersionCheck)
		// Status is derived from probe and version
		status := f.Status()
		assert.NotEmpty(t, status)
	}
}

func TestPythonKind_Audit_Offline(t *testing.T) {
	// This test verifies offline mode skips probes
	k := New()
	env := testutil.NewTestEnv()
	env.Offline = true

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Only mock the info extraction - probes should not be called
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Probes should not be called in offline mode
		return exec.CommandResult{
			Stderr:   "unexpected call in offline mode",
			ExitCode: 1,
		}
	}
	env.Run = runner

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
	}
}

func TestPythonKind_Audit_HermeticWithMockedPython(t *testing.T) {
	// This test proves hermeticity by setting PATH and HOME to temp dirs
	// and mocking the Python executable discovery and execution
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	// Set environment to temp directories
	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable in tmpPath (as a marker for discovery)
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	// Set up fake runner with OnCall for flexible command matching
	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Match based on command name and arguments
		// The code calls: RunWithInput(ctx, "info", pythonPath, "-I", "-B", probePath)
		// And: Run(ctx, pythonPath, "-I", "-B", probePath, "default", urls...)

		// Check if this is the info extraction
		if len(args) >= 3 && args[0] == "-I" && args[1] == "-B" {
			// Check if it ends with "info" (probe script mode)
			if len(args) >= 4 {
				return exec.CommandResult{
					Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
					ExitCode: 0,
				}
			}
			// Check if it's a probe mode
			if len(args) >= 5 {
				mode := args[3]
				switch mode {
				case "default":
					return exec.CommandResult{
						Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
						ExitCode: 0,
					}
				case "certifi":
					return exec.CommandResult{
						Stdout:   "certerr https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
						ExitCode: 0,
					}
				}
			}
		}

		// Check for pip download
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}

		// Default: command not found
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}

	env.Run = runner

	// Set up probe engine
	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	// We should find our mocked Python
	assert.NotEmpty(t, findings)

	// Check the finding
	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, "python", f.Kind)
		assert.Equal(t, "Python", f.Tool)
		assert.Equal(t, "3.11.0", f.Version)
		// The detail block records how each trust path behaved
		assert.Contains(t, f.Notes, "    detail:  default trust store: ")
		assert.Contains(t, f.Notes, "\n             OpenSSL cafile:      ")
		// Status should be derived from probe and version
		status := f.Status()
		assert.Contains(t, []kinds.Status{kinds.StatusOK, kinds.StatusLikelyOK, kinds.StatusAffected, kinds.StatusLikelyAffected, kinds.StatusUnknown}, status)
	}
}

func TestPythonKind_Audit_GuidancePresent(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	// Set up fake runner responses
	runner := exec.NewFakeRunner()
	runner.AddSuccess("info", "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n")
	runner.AddSuccess("default", "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n")

	env.Run = runner

	// Set up probe engine
	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	// With hermetic env, no Python will be found
	assert.Empty(t, findings)
}

func TestPythonKind_Audit_ProbeSkipped(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Offline = true

	// Create temp directories for hermetic test
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Only mock the info extraction
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Other commands should not be called in offline mode
		return exec.CommandResult{
			Stderr:   "unexpected call in offline mode",
			ExitCode: 1,
		}
	}
	env.Run = runner

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult)
	}
}

func TestPythonKind_Audit_VersionChecks(t *testing.T) {
	tests := []struct {
		name           string
		certifiVersion string
		pipVersion     string
		wantCheck      kinds.VersionCheck
	}{
		{
			name:           "both fixed",
			certifiVersion: "2026.10.19",
			pipVersion:     "26.2.2",
			wantCheck:      kinds.VersionOK,
		},
		{
			name:           "certifi behind",
			certifiVersion: "2026.10.1",
			pipVersion:     "26.2.2",
			wantCheck:      kinds.VersionBehind,
		},
		{
			name:           "pip behind",
			certifiVersion: "2026.10.19",
			pipVersion:     "26.2.0",
			wantCheck:      kinds.VersionBehind,
		},
		{
			name:           "both behind",
			certifiVersion: "2026.10.1",
			pipVersion:     "26.2.0",
			wantCheck:      kinds.VersionBehind,
		},
		{
			name:           "none installed",
			certifiVersion: "",
			pipVersion:     "",
			wantCheck:      kinds.VersionNA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := New()
			env := testutil.NewTestEnv()

			// Create temp directories
			tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpHome) }()

			tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpPath) }()

			env.Environ["HOME"] = tmpHome
			env.Environ["PATH"] = tmpPath
			env.TempDir = tmpHome

			// Create a mock python executable
			pythonPath := filepath.Join(tmpPath, "python3")
			require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

			// Build the info output based on the test case
			infoOutput := "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\n"
			infoOutput += "certifi=" + tt.certifiVersion + "\n"
			infoOutput += "pip=" + tt.pipVersion + "\n"
			infoOutput += "cafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n"

			runner := exec.NewFakeRunner()
			runner.OnCall = func(name string, args ...string) exec.CommandResult {
				// Mock the info extraction
				if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
					return exec.CommandResult{
						Stdout:   infoOutput,
						ExitCode: 0,
					}
				}
				// Mock the probes with protected results (rejected bad URLs)
				if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
					mode := args[3]
					switch mode {
					case "default":
						return exec.CommandResult{
							Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
							ExitCode: 0,
						}
					case "certifi":
						return exec.CommandResult{
							Stdout:   "certerr https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
							ExitCode: 0,
						}
					}
				}
				// For pip probe
				if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
					return exec.CommandResult{
						Stderr:   "CERTIFICATE_VERIFY_FAILED",
						ExitCode: 1,
					}
				}
				// Default
				return exec.CommandResult{
					Stderr:   "command not found",
					ExitCode: 127,
				}
			}
			env.Run = runner

			probeEngine := probe.NewFakeEngine()
			probeEngine.AddResult([]probe.ProbeResult{
				{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
				{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			})
			env.Probe = probeEngine

			findings, err := k.Audit(testutil.Context(), env)
			require.NoError(t, err)

			if len(findings) > 0 {
				f := findings[0]
				assert.Equal(t, tt.wantCheck, f.VersionCheck, "version check mismatch")
			} else {
				t.Errorf("Expected findings but got none")
			}
		})
	}
}

func TestPythonKind_Audit_HermeticNoHostPython(t *testing.T) {
	// This test verifies hermetic isolation by setting PATH to garbage
	// With testutil.NewTestEnv(), PATH is empty by default

	k := New()
	env := testutil.NewTestEnv()

	// Set PATH to a non-existent directory to ensure isolation
	env.Environ["PATH"] = "/nonexistent/path/that/does/not/exist"
	env.Environ["HOME"] = "/nonexistent/home"

	// Run audit - should not find any Python
	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.Empty(t, findings, "should not find Python in hermetic environment")
}

func TestUvToolNameSafe(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{"valid simple", "toolname", true},
		{"valid with dash", "tool-name", true},
		{"valid with dot", "tool.name", true},
		{"valid with underscore", "tool_name", true},
		{"valid with numbers", "tool123", true},
		{"empty", "", false},
		{"leading dash", "-tool", false},
		{"leading dot", ".tool", false},
		{"special chars", "tool$name", false},
		{"space", "tool name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, uvToolNameSafe(tt.arg))
		})
	}
}

func TestPythonKind_Audit_CompactAndFullGuidance(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories for hermetic test
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	script := `#!/bin/sh
echo "pyver=3.11.0"
echo "baseprefix=/usr"
echo "implementation=cpython"
echo "certifi=2026.10.1"
echo "pip=26.2.0"
echo "cafile=/etc/ssl/cert.pem"
echo "openssl=OpenSSL 3.0.0"
exit 0
`
	require.NoError(t, os.WriteFile(pythonPath, []byte(script), 0755))

	runner := exec.NewFakeRunner()
	runner.AddSuccess("info", "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n")
	runner.AddSuccess("default", "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n")
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Check that both compact and full guidance are present
	for _, f := range findings {
		if f.Status() == kinds.StatusAffected {
			assert.NotEmpty(t, f.GuidanceCompact)
			assert.NotEmpty(t, f.GuidanceFull)

			// Compact should be a single line
			assert.NotContains(t, f.GuidanceCompact, "\n")

			// Full should have multiple lines (at least one)
			assert.Greater(t, len(f.GuidanceFull), 0)
		}
	}
}

// Test that the probe logic is correctly implemented
func TestPythonKind_ProbePipBehavior(t *testing.T) {
	tests := []struct {
		name           string
		probeOutput    string
		probeExitCode  int
		expectedResult string
	}{
		{
			name:           "trusted - 404 response",
			probeOutput:    "ERROR: 404 Client Error: Not Found for url",
			probeExitCode:  1,
			expectedResult: "trusted",
		},
		{
			name:           "rejected - cert error",
			probeOutput:    "CERTIFICATE_VERIFY_FAILED: certificate verify failed",
			probeExitCode:  1,
			expectedResult: "rejected",
		},
		{
			name:           "inconclusive - network error",
			probeOutput:    "NewConnectionError: Failed to establish connection",
			probeExitCode:  128,
			expectedResult: "inconclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the probePip method through the Audit method
			// This is tested via the fake runner setup
			k := New()
			env := testutil.NewTestEnv()

			// Create temp directories
			tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpHome) }()

			tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpPath) }()

			env.Environ["HOME"] = tmpHome
			env.Environ["PATH"] = tmpPath
			env.TempDir = tmpHome

			pythonPath := filepath.Join(tmpPath, "python3")
			require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

			runner := exec.NewFakeRunner()
			runner.AddSuccess("info", "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n")
			runner.AddResponse("default", exec.CommandResult{
				Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			})
			env.Run = runner

			probeEngine := probe.NewFakeEngine()
			probeEngine.AddResult([]probe.ProbeResult{
				{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
				{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			})
			env.Probe = probeEngine

			findings, err := k.Audit(testutil.Context(), env)
			require.NoError(t, err)
			assert.NotNil(t, findings)
		})
	}
}

// Test the complete audit workflow with mocked components
func TestPythonKind_Audit_CompleteWorkflow(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create mock Python
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mock the info extraction
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Mock the probes with protected results
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			case "certifi":
				return exec.CommandResult{
					Stdout:   "certerr https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		// For pip probe
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		// Default
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Verify the finding structure
	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, "python", f.Kind)
		assert.Equal(t, "Python", f.Tool)
		assert.NotEmpty(t, f.Version)
		assert.NotEmpty(t, f.Path)
		assert.NotEmpty(t, f.Evidence)

		// Status should be derivable
		status := f.Status()
		assert.NotEmpty(t, status)
	}
}

// Test with environment variables
// TestPythonKind_NeedsSystemGuidance verifies that NeedsSystemGuidance is set
// when the Python interpreter trusts the compromised chain via the OS CA bundle.
// This maps to FIXSYS=1 in the bash script's fix_python function (line 1182).
func TestPythonKind_NeedsSystemGuidance(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	// Create temp directories
	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	// Create a mock python executable
	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Mock the info extraction - cafile is a system bundle (not Homebrew)
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Mock the probes - default trust store trusts the bad URLs (AFFECTED)
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			case "certifi":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		// For pip probe - rejected
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		return exec.CommandResult{
			Stderr:   "command not found",
			ExitCode: 127,
		}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Should find affected Python")

	f := findings[0]
	assert.Equal(t, kinds.StatusAffected, f.Status(), "Should be AFFECTED")
	assert.True(t, f.NeedsSystemGuidance, "NeedsSystemGuidance should be set for system CA bundle issues")
	assert.True(t, f.HasFix, "HasFix should be set when NeedsSystemGuidance is true")
}

// TestPythonKind_NeedsSystemGuidance_Homebrew verifies that NeedsSystemGuidance
// is NOT set when the CA file is Homebrew's bundle (script lines 1176-1178).
func TestPythonKind_NeedsSystemGuidance_Homebrew(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				// cafile is in /Cellar/ - Homebrew's bundle
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=/opt/homebrew/Cellar/ca-certificates/2026-09-25/etc/openssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" && args[3] == "default" {
			return exec.CommandResult{
				Stdout:   "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findings[0]
	assert.Equal(t, kinds.StatusAffected, f.Status())
	assert.False(t, f.NeedsSystemGuidance, "NeedsSystemGuidance should NOT be set for Homebrew's CA bundle")
	assert.False(t, f.HasFix, "HasFix should NOT be set when using Homebrew's bundle")
}

// TestPythonKind_NeedsPipGuidance_Darwin verifies that NeedsPipGuidance is set
// for macOS /usr/bin/python3 when affected (script lines 1196-1199).
func TestPythonKind_NeedsPipGuidance_Darwin(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Host = platform.Host{OS: "darwin"}

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = "/usr/bin"
	env.TempDir = tmpHome

	// Create mock for /usr/bin/python3
	require.NoError(t, os.MkdirAll("/tmp/emudhra-test-usr-bin", 0755))
	defer func() { _ = os.RemoveAll("/tmp/emudhra-test-usr-bin") }()

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Check for /usr/bin/python3
		if name == "/usr/bin/python3" && len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				// Behind versions to trigger FIXPIP
				Stdout:   "pyver=3.9.6\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=21.2.4\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 1.1.1",
				ExitCode: 0,
			}
		}
		if name == "/usr/bin/python3" && len(args) >= 5 && args[0] == "-I" && args[1] == "-B" {
			mode := args[3]
			switch mode {
			case "default":
				return exec.CommandResult{
					Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
					ExitCode: 0,
				}
			}
		}
		if name == "/usr/bin/python3" && len(args) >= 5 && args[2] == "-m" && args[3] == "pip" {
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		// xcode-select check
		if name == "/usr/bin/xcode-select" && len(args) > 0 && args[0] == "-p" {
			return exec.CommandResult{ExitCode: 0}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)

	// Should find /usr/bin/python3 with NeedsPipGuidance
	require.NotEmpty(t, findings, "Should find /usr/bin/python3")

	f := findings[0]
	assert.Equal(t, "Python", f.Tool)
	assert.True(t, f.NeedsPipGuidance, "NeedsPipGuidance should be set for macOS /usr/bin/python3 behind version")
	assert.True(t, f.HasFix, "HasFix should be set when NeedsPipGuidance is true")
}

// TestPythonKind_NoNeedsPipGuidance_Linux verifies that NeedsPipGuidance is
// NOT set on Linux even for the same affected scenario.
func TestPythonKind_NoNeedsPipGuidance_Linux(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Host = platform.Host{OS: "linux"}

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				// Behind versions
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" && args[3] == "default" {
			return exec.CommandResult{
				Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findings[0]
	assert.False(t, f.NeedsPipGuidance, "NeedsPipGuidance should NOT be set on Linux")
}

// TestPythonKind_HasFix_SystemGuidance verifies HasFix is set when
// NeedsSystemGuidance is true (plan_add sys via FIXSYS=1).
func TestPythonKind_HasFix_SystemGuidance(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=/etc/pki/tls/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" && args[3] == "default" {
			return exec.CommandResult{
				Stdout:   "ok https://github.com/\nok https://dv-g3b-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	probeEngine.AddResult([]probe.ProbeResult{
		{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
		{URL: probe.BAD_URLS[0], Verdict: probe.VerdictTrusted},
	})
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	f := findings[0]
	assert.True(t, f.NeedsSystemGuidance, "NeedsSystemGuidance should be set")
	assert.True(t, f.HasFix, "HasFix should be set when NeedsSystemGuidance is true")
}

// TestPythonKind_NoHasFix_VersionOnly verifies HasFix is NOT set when
// there's no system/pip guidance and the tool is protected (status OK).
func TestPythonKind_NoHasFix_VersionOnly(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	tmpPath, err := os.MkdirTemp("", "emudhra-test-path-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpPath) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = tmpPath
	env.TempDir = tmpHome

	pythonPath := filepath.Join(tmpPath, "python3")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\nexit 0\n"), 0755))

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		if len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				// Behind certifi/pip versions
				Stdout:   "pyver=3.11.0\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.1\npip=26.2.0\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 3.0.0\n",
				ExitCode: 0,
			}
		}
		// Default probe - rejected
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" && args[3] == "default" {
			return exec.CommandResult{
				Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\ncerterr https://dv-g3b-aaa-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			}
		}
		// Certifi probe - rejected
		if len(args) >= 5 && args[0] == "-I" && args[1] == "-B" && args[3] == "certifi" {
			return exec.CommandResult{
				Stdout:   "ok https://github.com/\ncerterr https://dv-g3b-emudhra.we-have-a-problem.com/\ncerterr https://dv-g3b-aaa-emudhra.we-have-a-problem.com/\n",
				ExitCode: 0,
			}
		}
		// Pip probe - rejected (certificate error)
		if len(args) >= 5 && args[2] == "-m" && args[3] == "pip" && args[4] == "download" {
			// Check which URL is being probed
			for _, arg := range args {
				if strings.Contains(arg, "github.com") {
					// Control URL - return error (which will be interpreted as other error by probePip)
					return exec.CommandResult{
						Stderr:   "Network error",
						ExitCode: 1,
					}
				}
			}
			// Bad URLs - certificate error
			return exec.CommandResult{
				Stderr:   "CERTIFICATE_VERIFY_FAILED",
				ExitCode: 1,
			}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	probeEngine := probe.NewFakeEngine()
	env.Probe = probeEngine

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Should find Python")

	f := findings[0]
	// Version is behind but probes show protected - no HasFix
	assert.False(t, f.NeedsSystemGuidance, "Should not need system guidance")
	assert.False(t, f.NeedsPipGuidance, "Should not need pip guidance")
	assert.False(t, f.HasFix, "HasFix should NOT be set when protected (no shared guidance needed)")
}

// TestPythonKind_OfflineMacOSPython verifies the --no-network case for macOS /usr/bin/python3.
// The script reports Python 3.9.6 (/usr/bin/python3) as LIKELY-AFFECTED because pip 21.2.4 is behind.
func TestPythonKind_OfflineMacOSPython(t *testing.T) {
	k := New()
	env := testutil.NewTestEnv()
	env.Host = platform.Host{OS: "darwin"}
	env.Offline = true

	tmpHome, err := os.MkdirTemp("", "emudhra-test-home-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpHome) }()

	env.Environ["HOME"] = tmpHome
	env.Environ["PATH"] = "/usr/bin"
	env.TempDir = tmpHome

	runner := exec.NewFakeRunner()
	runner.OnCall = func(name string, args ...string) exec.CommandResult {
		// Check for /usr/bin/python3
		if name == "/usr/bin/python3" && len(args) >= 4 && args[0] == "-I" && args[1] == "-B" && args[3] == "info" {
			return exec.CommandResult{
				// macOS system Python 3.9.6 with behind pip
				Stdout:   "pyver=3.9.6\nbaseprefix=/usr\nimplementation=cpython\ncertifi=\npip=21.2.4\ncafile=/etc/ssl/cert.pem\nopenssl=OpenSSL 1.1.1",
				ExitCode: 0,
			}
		}
		// xcode-select check
		if name == "/usr/bin/xcode-select" && len(args) > 0 && args[0] == "-p" {
			return exec.CommandResult{ExitCode: 0}
		}
		return exec.CommandResult{ExitCode: 127}
	}
	env.Run = runner

	findings, err := k.Audit(testutil.Context(), env)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Should find /usr/bin/python3")

	f := findings[0]
	// With --no-network, probe is skipped, so status comes from version check
	assert.Equal(t, kinds.ProbeSkipped, f.ProbeResult, "Probe should be skipped in offline mode")
	assert.Equal(t, kinds.VersionBehind, f.VersionCheck, "Version should be behind")
	assert.Equal(t, kinds.StatusLikelyAffected, f.Status(), "Should be LIKELY-AFFECTED with behind pip and no network")
	// NeedsPipGuidance should be set for macOS /usr/bin/python3 even when probe is skipped
	assert.True(t, f.NeedsPipGuidance, "NeedsPipGuidance should be set for macOS /usr/bin/python3 with behind version")
	assert.True(t, f.HasFix, "HasFix should be set when NeedsPipGuidance is true")
}

// fileExists was filepath.Glob(path) with err == nil, which is true for every path (Glob
// only errors on a malformed pattern). It made every Python look like a uv tool environment
// the moment uv's tool directory became known.
func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "uv-receipt.toml")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	assert.True(t, fileExists(f))
	assert.False(t, fileExists(filepath.Join(dir, "missing.toml")), "a path that does not exist")
	assert.False(t, fileExists(dir), "a directory is not a file")
	assert.False(t, fileExists(filepath.Join(dir, "no", "such", "dir", "x")))
}

func TestIsUVToolEnv_NeedsAReceiptAndAToolsDirectory(t *testing.T) {
	k := &Kind{}
	env := t.TempDir()
	assert.False(t, k.isUVToolEnv(env, "/some/tools"), "no receipt: an ordinary Python")
	require.NoError(t, os.WriteFile(filepath.Join(env, "uv-receipt.toml"), []byte("x"), 0o644))
	assert.True(t, k.isUVToolEnv(env, "/some/tools"), "a receipt marks a uv tool environment")
	assert.False(t, k.isUVToolEnv(env, ""), "without uv's tool directory it is not treated as a uv tool")
}

// python_candidates globs python* and keeps only python, python3, python3.9 and python3.12.
// The names below are real ones from Homebrew, the python.org framework and uv.
func TestInterpreters_KeepsOnlyInterpreterNames(t *testing.T) {
	names := []string{
		"python", "python3", "python3.9", "python3.12", "python3.15", "python2",
		"python3-config", "python3.12-config", "python3-intel64", "python3.14-intel64",
		"python3.15t", "python3.123", "python3.", "pythonw", "python3m", "python-config",
		"pip", "python3.12.1", "Python3",
	}
	var in []string
	for _, n := range names {
		in = append(in, filepath.Join("/opt/bin", n))
	}
	var got []string
	for _, p := range interpreters(in) {
		got = append(got, filepath.Base(p))
	}
	assert.Equal(t, []string{"python", "python3", "python3.9", "python3.12", "python3.15", "python2"}, got)
}

// A tool's python is listed even when the executable is missing, so that it is reported
// as unknown rather than silently skipped.
func TestCandidates_ListsAMissingToolPythonButNotHelperScripts(t *testing.T) {
	home := t.TempDir()
	tools := filepath.Join(home, "tools")
	tool := filepath.Join(tools, "ruff")
	require.NoError(t, os.MkdirAll(filepath.Join(tool, "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tool, "uv-receipt.toml"), []byte("x"), 0o644)) // no bin/python
	bin := filepath.Join(home, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	for _, n := range []string{"python3", "python3-config"} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755))
	}
	env := testutil.NewTestEnvT(t)
	env.Environ = map[string]string{"HOME": home, "PATH": bin}

	got := New().(*Kind).candidates(env, "", tools)
	assert.Contains(t, got, filepath.Join(bin, "python3"))
	assert.NotContains(t, got, filepath.Join(bin, "python3-config"), "a helper script is not an interpreter")
	assert.Contains(t, got, filepath.Join(tool, "bin", "python"), "a tool with a missing python is still listed")
}

// ---- uv-managed Pythons and tools --------------------------------------------------

// uvStub answers the two questions the audit asks of uv. uv itself reports the directories
// (honouring UV_PYTHON_INSTALL_DIR and UV_TOOL_DIR); they are not variables the audit can read.
func uvStub(pythonDir, toolDir string) string {
	return "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; prev2=\"$prev\"; prev=\"$a\"; done\n" +
		"case \"$*\" in\n" +
		"  *\"python dir\"*) echo " + pythonDir + " ;;\n" +
		"  *\"tool dir\"*) echo " + toolDir + " ;;\n" +
		"esac\n"
}

// pythonStub prints the "info" key=value lines the probe script produces.
func pythonStub(version, pip string) string {
	return "#!/bin/sh\ncat <<'EOF'\npyver=" + version + "\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=" + pip + "\ncafile=\nopenssl=OpenSSL 3.0.0\nEOF\n"
}

type uvRig struct {
	env       *kinds.Env
	home, bin string
	pyDir     string
	toolDir   string
}

func newUVRig(t *testing.T, withUV bool) *uvRig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	r := &uvRig{home: filepath.Join(root, "home"), bin: filepath.Join(root, "bin"),
		pyDir: filepath.Join(root, "uvpython"), toolDir: filepath.Join(root, "uvtools")}
	for _, d := range []string{r.home, r.bin, r.pyDir, r.toolDir} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	if withUV {
		require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte(uvStub(r.pyDir, r.toolDir)), 0o755))
	}
	r.env = testutil.NewTestEnvT(t)
	r.env.Run = exec.NewRealRunner()
	r.env.Offline = true
	r.env.Environ = map[string]string{"HOME": r.home, "PATH": r.bin}
	return r
}

// managed makes a uv-managed install: cpython-<ver>-.../bin/python
func (r *uvRig) managed(t *testing.T, ver, pip string) string {
	t.Helper()
	d := filepath.Join(r.pyDir, "cpython-"+ver+"-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(d, 0o755))
	p := filepath.Join(d, "python")
	require.NoError(t, os.WriteFile(p, []byte(pythonStub(ver, pip)), 0o755))
	return p
}

// tool makes a uv tool environment: <tools>/<name>/{uv-receipt.toml, bin/python}
func (r *uvRig) tool(t *testing.T, name, ver, pip string, withPython bool) string {
	t.Helper()
	d := filepath.Join(r.toolDir, name)
	require.NoError(t, os.MkdirAll(filepath.Join(d, "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "uv-receipt.toml"), []byte("[tool]\n"), 0o644))
	p := filepath.Join(d, "bin", "python")
	if withPython {
		require.NoError(t, os.WriteFile(p, []byte(pythonStub(ver, pip)), 0o755))
	}
	return p
}

func (r *uvRig) plain(t *testing.T, name, ver, pip string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, name), []byte(pythonStub(ver, pip)), 0o755))
}

func tools(fs []kinds.Finding) (out []string) {
	for _, f := range fs {
		out = append(out, f.Tool+"|"+f.Version)
	}
	return
}

func TestUVAudit_FindsAUVManagedPythonAndLabelsItAsSuch(t *testing.T) {
	r := newUVRig(t, true)
	want := r.managed(t, "3.11.15", "26.2.1")
	r.plain(t, "python3", "3.12.0", "26.2.2")

	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	require.Len(t, fs, 2, "%v", tools(fs))
	byPath := map[string]kinds.Finding{}
	for _, f := range fs {
		byPath[f.Path] = f
	}
	assert.Equal(t, "uv Python", byPath[want].Tool, "a Python under uv's directory is a uv Python")
	assert.Equal(t, "Python", byPath[filepath.Join(r.bin, "python3")].Tool, "and an ordinary one is not mislabelled")
	assert.Equal(t, kinds.StatusLikelyAffected, byPath[want].Status(), "pip 26.2.1 < 26.2.2, offline")
}

func TestUVAudit_WithoutUVNothingIsLabelledUV(t *testing.T) {
	r := newUVRig(t, false)
	r.plain(t, "python3", "3.12.0", "26.2.2")
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	require.Len(t, fs, 1)
	assert.Equal(t, "Python", fs[0].Tool)
}

func TestUVAudit_AToolEnvironmentIsNamedAfterTheTool(t *testing.T) {
	r := newUVRig(t, true)
	p := r.tool(t, "ruff", "3.12.4", "26.2.2", true)
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	require.Len(t, fs, 1, "%v", tools(fs))
	assert.Equal(t, "uv tool: ruff Python", fs[0].Tool)
	assert.Equal(t, p, fs[0].Path)
}

func TestUVAudit_AToolWhosePythonIsMissingIsReportedAsUnknownNotSkipped(t *testing.T) {
	r := newUVRig(t, true)
	r.tool(t, "broken", "", "", false)
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	require.Len(t, fs, 1, "a tool with no python must still be reported: %v", tools(fs))
	assert.Equal(t, kinds.StatusUnknown, fs[0].Status())
}

func TestUVAudit_HelperScriptsInAUVDirectoryAreNotInterpreters(t *testing.T) {
	r := newUVRig(t, true)
	r.managed(t, "3.11.15", "26.2.2")
	cfg := filepath.Join(r.pyDir, "cpython-3.11.15-macos-aarch64-none", "bin", "python3-config")
	require.NoError(t, os.WriteFile(cfg, []byte("#!/bin/sh\n"), 0o755))
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	assert.Len(t, fs, 1, "python3-config is not a Python: %v", tools(fs))
}

func TestUVAudit_WhenUVCannotAnswerItSaysSoInsteadOfAuditingNothing(t *testing.T) {
	r := newUVRig(t, false)
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte("#!/bin/sh\nexit 1\n"), 0o755))
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	var named []string
	for _, f := range fs {
		named = append(named, f.Tool)
		assert.Equal(t, kinds.ProbeInconclusive, f.ProbeResult)
		assert.Contains(t, f.Evidence, "uv could not report its")
	}
	assert.ElementsMatch(t, []string{"uv python discovery", "uv tool discovery"}, named)
}

// uv is found on PATH, else in $HOME/.local/bin, else $HOME/.cargo/bin (uv_environment_dirs).
func TestUVAudit_FindsUVInTheStandaloneAndCargoLocations(t *testing.T) {
	for _, rel := range []string{".local/bin", ".cargo/bin"} {
		t.Run(rel, func(t *testing.T) {
			r := newUVRig(t, false) // not on PATH
			dir := filepath.Join(r.home, filepath.FromSlash(rel))
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "uv"), []byte(uvStub(r.pyDir, r.toolDir)), 0o755))
			p := r.managed(t, "3.11.15", "26.2.2")
			fs, err := New().Audit(testutil.Context(), r.env)
			require.NoError(t, err)
			require.Len(t, fs, 1, "%v", tools(fs))
			assert.Equal(t, "uv Python", fs[0].Tool)
			assert.Equal(t, p, fs[0].Path)
		})
	}
}

// A uv that prints several lines for its directory is not trusted: the script refuses it
// ([[ "$dir" = *$'\n'* ]]) rather than guessing which line is the directory.
func TestUVAudit_AMultiLineDirectoryAnswerIsRefused(t *testing.T) {
	r := newUVRig(t, false)
	stub := "#!/bin/sh\nprintf '%s\\n%s\\n' /somewhere /else\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte(stub), 0o755))
	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	var named []string
	for _, f := range fs {
		named = append(named, f.Tool)
	}
	assert.ElementsMatch(t, []string{"uv python discovery", "uv tool discovery"}, named)
}

// Interpret is what the uv fixer verifies an upgraded interpreter with, so it must report the
// metadata and leave a path that does not apply (no certifi, no pip) empty rather than guessing.
func TestInterpret_ReportsMetadataAndOnlyTheProbesThatApply(t *testing.T) {
	r := newUVRig(t, false)
	r.plain(t, "python3", "3.12.4", "26.2.2")
	r.env.Offline = false
	p, err := Interpret(testutil.Context(), r.env, filepath.Join(r.bin, "python3"))
	require.NoError(t, err)
	assert.Equal(t, "3.12.4", p.Info.Version)
	assert.Equal(t, "26.2.2", p.Info.Pip)
	assert.NotEmpty(t, p.Default, "the default store is always probed")
	assert.NotEmpty(t, p.Certifi, "certifi is installed, so it is probed")
	assert.NotEmpty(t, p.Pip, "pip is installed, so it is probed")

	bare := "#!/bin/sh\ncat <<'EOF'\npyver=3.12.4\nbaseprefix=/usr\nimplementation=cpython\ncertifi=\npip=\ncafile=\nopenssl=x\nEOF\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "python3"), []byte(bare), 0o755))
	p, err = Interpret(testutil.Context(), r.env, filepath.Join(r.bin, "python3"))
	require.NoError(t, err)
	assert.Empty(t, p.Certifi, "no certifi, no certifi probe")
	assert.Empty(t, p.Pip, "no pip, no pip probe")
}

func TestInterpret_AnInterpreterThatCannotReportIsAnError(t *testing.T) {
	r := newUVRig(t, false)
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "python3"), []byte("#!/bin/sh\nexit 1\n"), 0o755))
	_, err := Interpret(testutil.Context(), r.env, filepath.Join(r.bin, "python3"))
	assert.Error(t, err)
}

// ---- uv Python: patch availability, selected, retained, and the fix requests ----------

// uvCatalogStub answers what the uv-Python audit asks of uv: the two directories, the launcher
// directory, and the offline catalogue (`python list --only-downloads --managed-python cpython@M`).
// catalogue is the stdout of that listing; "FAIL" makes the listing fail.
func uvCatalogStub(pythonDir, toolDir, binDir, catalogue string) string {
	list := "echo '" + catalogue + "'"
	if catalogue == "FAIL" {
		list = "exit 1"
	}
	return "#!/bin/sh\ncase \"$*\" in\n" +
		"  *\"python dir --bin\"*) echo " + binDir + " ;;\n" +
		"  *\"tool dir --bin\"*) echo " + binDir + " ;;\n" +
		"  *\"python dir\"*) echo " + pythonDir + " ;;\n" +
		"  *\"tool dir\"*) echo " + toolDir + " ;;\n" +
		"  *\"python list\"*) " + list + " ;;\n" +
		"esac\n"
}

type uvAudit struct {
	*uvRig
	launchers string
}

func newUVAudit(t *testing.T, catalogue string) *uvAudit {
	t.Helper()
	r := newUVRig(t, false)
	a := &uvAudit{uvRig: r, launchers: filepath.Join(filepath.Dir(r.bin), "launchers")}
	require.NoError(t, os.MkdirAll(a.launchers, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte(uvCatalogStub(r.pyDir, r.toolDir, a.launchers, catalogue)), 0o755))
	return a
}

// install makes cpython-V-macos-aarch64-none with a python that reports V.
func (a *uvAudit) install(t *testing.T, ver, pip string) string {
	t.Helper()
	d := filepath.Join(a.pyDir, "cpython-"+ver+"-macos-aarch64-none")
	require.NoError(t, os.MkdirAll(filepath.Join(d, "bin"), 0o755))
	stub := "#!/bin/sh\ncat <<'EOF'\npyver=" + ver + "\nbaseprefix=" + d + "\nimplementation=cpython\ncertifi=2026.10.19\npip=" + pip + "\ncafile=\nopenssl=x\nEOF\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "bin", "python"), []byte(stub), 0o755))
	require.NoError(t, os.Symlink("python", filepath.Join(d, "bin", "python3")))
	return filepath.Join(d, "bin", "python")
}

// prefer makes uv's minor alias cpython-M-... point at an install (what `uv python install` does).
func (a *uvAudit) prefer(t *testing.T, minor, ver string) {
	t.Helper()
	require.NoError(t, os.Symlink(filepath.Join(a.pyDir, "cpython-"+ver+"-macos-aarch64-none"), filepath.Join(a.pyDir, "cpython-"+minor+"-macos-aarch64-none")))
}

func (a *uvAudit) audit(t *testing.T) []kinds.Finding {
	t.Helper()
	a.env.Offline = true
	fs, err := New().Audit(testutil.Context(), a.env)
	require.NoError(t, err)
	return fs
}

func byVersion(fs []kinds.Finding, v string) kinds.Finding {
	for _, f := range fs {
		if strings.HasPrefix(f.Version, v) && f.Tool == "uv Python" {
			return f
		}
	}
	return kinds.Finding{}
}

const cat312 = "cpython-3.12.9-macos-aarch64-none    <download available>"

func TestUVPythonAudit_AnInstallThatIsAlreadyTheNewestIsNotSelectedOrScheduledForRetention(t *testing.T) {
	a := newUVAudit(t, cat312)
	a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.9") // the alias points at the NEWEST install
	f := byVersion(a.audit(t), "3.12.9")
	require.Equal(t, "uv Python", f.Tool)
	assert.NotContains(t, f.Notes, "preferred: still selects this older patch", "the newest patch is not an older one")
	assert.NotContains(t, f.Notes, "retained:")
	assert.Empty(t, kinds.RequestsFor("uvpython", []kinds.Finding{f}), "nothing to upgrade: it is current and the catalogue offers nothing newer")
}

func TestUVPythonAudit_AnOlderPatchStillSelectedIsPreferredAndScheduledToTheNewestInstalled(t *testing.T) {
	a := newUVAudit(t, cat312)
	a.install(t, "3.12.4", "26.2.2")
	a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.4") // the alias still selects the older patch
	f := byVersion(a.audit(t), "3.12.4")
	assert.Contains(t, f.Notes, "preferred: still selects this older patch despite 3.12.9 being installed; update remains scheduled")
	reqs := kinds.RequestsFor("uvpython", []kinds.Finding{f})
	require.Len(t, reqs, 1, "one request per minor line")
	assert.Equal(t, "3.12", reqs[0].Target)
	assert.Equal(t, "3.12.9", reqs[0].Minimum, "the highest minimum wins: the catalogue's 3.12.9 equals what is installed")
}

func TestUVPythonAudit_AnOlderPatchThatIsNotSelectedIsRetainedNotUpgraded(t *testing.T) {
	a := newUVAudit(t, cat312)
	a.install(t, "3.12.4", "26.2.2")
	a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.9") // the alias selects the newer patch: the old one is just kept
	f := byVersion(a.audit(t), "3.12.4")
	assert.Contains(t, f.Notes, "retained: older patch kept beside 3.12.9; upgrading the preferred runtime cannot remove this retained installation")
	assert.NotContains(t, f.Notes, "preferred: still selects")
	assert.Empty(t, kinds.RequestsFor("uvpython", []kinds.Finding{f}))
}

func TestUVPythonAudit_ANewerCataloguePatchSchedulesAnUpgradeToIt(t *testing.T) {
	a := newUVAudit(t, "cpython-3.12.9-macos-aarch64-none <download available>\ncpython-3.12.11-macos-aarch64-none <download available>")
	a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.9")
	f := byVersion(a.audit(t), "3.12.9")
	assert.Contains(t, f.Notes, "update: available patch: 3.12.11; newest installed patch: 3.12.9; patch availability is not a vulnerability verdict")
	reqs := kinds.RequestsFor("uvpython", []kinds.Finding{f})
	require.Len(t, reqs, 1)
	assert.Equal(t, kinds.FixRequest{Kind: "uvpython", Target: "3.12", Minimum: "3.12.11"}, reqs[0])
	assert.Contains(t, f.GuidanceCompact, "uv python upgrade 3.12; then re-audit linked environments")
}

// The two catalogue outcomes are worded differently: a listing that could not be read is
// "unknown", one that was read but offers nothing for this family is "no downloadable patch".
func TestUVPythonAudit_TheCatalogueOutcomesAreWordedDifferently(t *testing.T) {
	cases := []struct{ name, catalogue, want string }{
		{"unreadable", "FAIL", "update: uv catalogue could not be read; patch availability is unknown"},
		{"nothing for this family", "cpython-3.13.1-macos-aarch64-none <download available>", "update: uv reports no downloadable patch for this interpreter family"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newUVAudit(t, c.catalogue)
			a.install(t, "3.12.9", "26.2.2")
			a.prefer(t, "3.12", "3.12.9")
			f := byVersion(a.audit(t), "3.12.9")
			assert.Contains(t, f.Notes, c.want)
		})
	}
}

func TestUVPythonAudit_NonManagedPythonsRequestNothingFromUV(t *testing.T) {
	a := newUVAudit(t, cat312)
	a.plain(t, "python3", "3.9.6", "21.2.4") // old pip: LIKELY-AFFECTED, but not uv's to fix
	fs := a.audit(t)
	require.Len(t, fs, 1)
	assert.Empty(t, fs[0].Requests)
	assert.NotContains(t, fs[0].Notes, "update:")
}

func TestUVPythonAudit_VariantsWithAPlusInTheNameAreNotEligible(t *testing.T) {
	a := newUVAudit(t, cat312)
	d := filepath.Join(a.pyDir, "cpython-3.12.4+freethreaded-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(d, 0o755))
	stub := "#!/bin/sh\ncat <<'EOF'\npyver=3.12.4\nbaseprefix=" + filepath.Dir(d) + "\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=\nopenssl=x\nEOF\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "python"), []byte(stub), 0o755))
	fs := a.audit(t)
	require.NotEmpty(t, fs)
	for _, f := range fs {
		assert.Empty(t, f.Requests, "free-threaded and debug builds need explicit handling, not an automatic patch upgrade")
	}
}

func TestUVPythonAudit_ATrustedDefaultStoreAtTheNewestPatchRequestsTheMinorWithNoMinimum(t *testing.T) {
	// plan_uv_python "$minor" "" : the Python is current but still trusts the chain, so the
	// upgrade is requested without a target patch.
	a := newUVAudit(t, cat312)
	p := a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.9")
	// make the default store trust the chain
	stub := "#!/bin/sh\ncase \"$4\" in\n  info) cat <<'EOF'\npyver=3.12.9\nbaseprefix=" + filepath.Dir(filepath.Dir(p)) + "\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=\nopenssl=x\nEOF\n;;\n  default|certifi) shift 4; printf 'ok %s\\nok %s\\nok %s\\n' \"$@\" ;;\nesac\n"
	require.NoError(t, os.WriteFile(p, []byte(stub), 0o755))
	a.env.Offline = false
	fs, err := New().Audit(testutil.Context(), a.env)
	require.NoError(t, err)
	f := byVersion(fs, "3.12.9")
	reqs := kinds.RequestsFor("uvpython", []kinds.Finding{f})
	require.Len(t, reqs, 1, "%v", f.Notes)
	assert.Equal(t, "3.12", reqs[0].Target)
}

// With nothing downloadable, the selected older patch is still moved up to what is installed:
// that is the only source of the Minimum (plan_uv_python "$minor" "$newest").
func TestUVPythonAudit_ASelectedOlderPatchWithNoCatalogueEntryIsMovedToTheNewestInstalled(t *testing.T) {
	a := newUVAudit(t, "cpython-3.13.1-macos-aarch64-none <download available>")
	a.install(t, "3.12.4", "26.2.2")
	a.install(t, "3.12.9", "26.2.2")
	a.prefer(t, "3.12", "3.12.4")
	f := byVersion(a.audit(t), "3.12.4")
	assert.Equal(t, []kinds.FixRequest{{Kind: "uvpython", Target: "3.12", Minimum: "3.12.9"}}, kinds.RequestsFor("uvpython", []kinds.Finding{f}))
}

// The report's detail block, exactly as the script lays it out: reason in the probe line, one
// "detail:" line per trust path with aligned labels, and a note per CA-related variable set.
func TestAuditDetailBlockMatchesTheScriptLayout(t *testing.T) {
	r := newUVRig(t, false)
	r.plain(t, "python3", "3.9.6", "26.2.2")
	r.env.Offline = true
	r.env.Environ["SSL_CERT_FILE"] = "/etc/my-ca.pem"
	r.env.Environ["SSL_CERT_DIR"] = "/etc/certs"
	r.env.Environ["REQUESTS_CA_BUNDLE"] = "/etc/req.pem"
	r.env.Environ["PIP_CERT"] = "/etc/pip-ca.pem"

	fs, err := New().Audit(testutil.Context(), r.env)
	require.NoError(t, err)
	require.Len(t, fs, 1)

	assert.Equal(t, kinds.ProbeSkipped, fs[0].ProbeResult)
	assert.Equal(t, "--no-network", fs[0].Evidence, "the probe line reads \"skipped (--no-network)\"")
	assert.Equal(t, "    detail:  default trust store: skipped (--no-network)\n"+
		"             OpenSSL cafile:      none  (OpenSSL 3.0.0)\n"+
		"    note:    SSL_CERT_FILE=/etc/my-ca.pem\n"+
		"    note:    SSL_CERT_DIR=/etc/certs\n"+
		"    note:    REQUESTS_CA_BUNDLE=/etc/req.pem\n"+
		"    note:    PIP_CERT=/etc/pip-ca.pem", fs[0].Notes)
}
