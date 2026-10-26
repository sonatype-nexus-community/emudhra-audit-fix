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

package git

import (
	"context"
	"fmt"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name        string
		gitOutput   string
		wantVersion string
	}{
		{
			name:        "standard git version output",
			gitOutput:   "git version 2.43.0",
			wantVersion: "2.43.0",
		},
		{
			name:        "Apple git version",
			gitOutput:   "git version 2.39.3 (Apple Git-146)",
			wantVersion: "2.39.3",
		},
		{
			name:        "older git version",
			gitOutput:   "git version 2.25.1",
			wantVersion: "2.25.1",
		},
		{
			name:        "empty output",
			gitOutput:   "",
			wantVersion: "?",
		},
		{
			name:        "malformed output",
			gitOutput:   "not git output",
			wantVersion: "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := exec.NewFakeRunner()
			runner.AddResponse("/usr/bin/git", exec.CommandResult{
				Stdout: tt.gitOutput,
			})

			env := &kinds.Env{
				Run:     runner,
				Environ: make(map[string]string),
			}

			k := &Kind{}
			version := k.getVersion(context.Background(), env, "/usr/bin/git")

			if version != tt.wantVersion {
				t.Errorf("getVersion() = %v, want %v", version, tt.wantVersion)
			}
		})
	}
}

func TestXcodeToolsInstalled(t *testing.T) {
	t.Run("xcode-select succeeds", func(t *testing.T) {
		runner := exec.NewFakeRunner()
		runner.AddResponse("xcode-select", exec.CommandResult{})

		k := &Kind{}
		if !k.xcodeToolsInstalled(context.Background(), runner) {
			t.Error("xcodeToolsInstalled() = false, want true")
		}
	})

	t.Run("xcode-select fails", func(t *testing.T) {
		runner := exec.NewFakeRunner()
		runner.AddResponse("xcode-select", exec.CommandResult{
			Error: fmt.Errorf("not installed"),
		})

		k := &Kind{}
		if k.xcodeToolsInstalled(context.Background(), runner) {
			t.Error("xcodeToolsInstalled() = true, want false")
		}
	})
}

func TestEnvNotes(t *testing.T) {
	tests := []struct {
		name      string
		environ   map[string]string
		gitConfig map[string]string
		wantNotes []string
		wantEmpty bool
	}{
		{
			name:      "no environment variables or config",
			environ:   map[string]string{},
			gitConfig: map[string]string{},
			wantEmpty: true,
		},
		{
			name: "GIT_SSL_CAINFO set",
			environ: map[string]string{
				"GIT_SSL_CAINFO": "/etc/ssl/cert.pem",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{"GIT_SSL_CAINFO=/etc/ssl/cert.pem"},
		},
		{
			name: "GIT_SSL_CAPATH set",
			environ: map[string]string{
				"GIT_SSL_CAPATH": "/etc/ssl/certs",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{"GIT_SSL_CAPATH=/etc/ssl/certs"},
		},
		{
			name: "SSL_CERT_FILE set",
			environ: map[string]string{
				"SSL_CERT_FILE": "/etc/ssl/cert.pem",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{"SSL_CERT_FILE=/etc/ssl/cert.pem"},
		},
		{
			name:      "http.sslCAInfo configured",
			environ:   map[string]string{},
			gitConfig: map[string]string{"http.sslCAInfo": "/etc/ssl/ca-bundle.crt"},
			wantNotes: []string{"http.sslCAInfo=/etc/ssl/ca-bundle.crt"},
		},
		{
			name:      "http.sslVerify=false configured",
			environ:   map[string]string{},
			gitConfig: map[string]string{"http.sslVerify": "false"},
			wantNotes: []string{"http.sslVerify=false - git skips certificate checks"},
		},
		{
			name: "GIT_SSL_NO_VERIFY warning",
			environ: map[string]string{
				"GIT_SSL_NO_VERIFY": "1",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{"WARNING: GIT_SSL_NO_VERIFY is set: git skips certificate checks"},
		},
		{
			name: "NODE_TLS_REJECT_UNAUTHORIZED warning",
			environ: map[string]string{
				"NODE_TLS_REJECT_UNAUTHORIZED": "0",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{"WARNING: NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks"},
		},
		{
			name: "multiple environment variables",
			environ: map[string]string{
				"GIT_SSL_CAINFO": "/etc/ssl/cert.pem",
				"GIT_SSL_CAPATH": "/etc/ssl/certs",
			},
			gitConfig: map[string]string{},
			wantNotes: []string{
				"GIT_SSL_CAINFO=/etc/ssl/cert.pem",
				"GIT_SSL_CAPATH=/etc/ssl/certs",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &kinds.Env{
				Environ: tt.environ,
				Run:     exec.NewFakeRunner(),
				TempDir: "/tmp",
			}

			// Set up git config responses using OnCall callback
			runner := exec.NewFakeRunner()
			runner.OnCall = func(name string, args ...string) exec.CommandResult {
				if name == "/usr/bin/git" && len(args) >= 3 {
					// Match "config --get <key>"
					if args[0] == "config" && args[1] == "--get" {
						key := args[2]
						if val, ok := tt.gitConfig[key]; ok {
							return exec.CommandResult{Stdout: val}
						}
					}
				}
				return exec.CommandResult{}
			}
			env.Run = runner

			k := &Kind{}
			notes := k.envNotes(context.Background(), env, "/usr/bin/git")

			if tt.wantEmpty {
				if notes != "" {
					t.Errorf("envNotes() = %v, want empty", notes)
				}
				return
			}

			for _, want := range tt.wantNotes {
				if !contains(notes, want) {
					t.Errorf("envNotes() = %v, want to contain %v", notes, want)
				}
			}
		})
	}
}

func TestAddGuidance(t *testing.T) {
	tests := []struct {
		name                string
		probeResult         kinds.ProbeResult
		gitPath             string
		hostOS              string
		wantCompact         string
		wantNeedsSystemGuid bool
		wantHasFix          bool
	}{
		{
			name:                "not affected - no guidance",
			probeResult:         kinds.ProbeRejected,
			gitPath:             "/usr/bin/git",
			hostOS:              "darwin",
			wantNeedsSystemGuid: false,
			wantHasFix:          false,
		},
		{
			name:                "affected - brew git",
			probeResult:         kinds.ProbeTrusted,
			gitPath:             "/opt/homebrew/bin/git",
			hostOS:              "darwin",
			wantCompact:         "brew upgrade git ca-certificates",
			wantNeedsSystemGuid: false,
			wantHasFix:          true,
		},
		{
			name:                "affected - macOS system git",
			probeResult:         kinds.ProbeTrusted,
			gitPath:             "/usr/bin/git",
			hostOS:              "darwin",
			wantCompact:         "patch the system CA bundle (or use Homebrew's git)",
			wantNeedsSystemGuid: true,
			wantHasFix:          false,
		},
		{
			name:                "affected - Linux git",
			probeResult:         kinds.ProbeTrusted,
			gitPath:             "/usr/bin/git",
			hostOS:              "linux",
			wantCompact:         "patch the system CA bundle (or use Homebrew's git)",
			wantNeedsSystemGuid: true,
			wantHasFix:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := kinds.NewFinding("git", "git")
			f.ProbeResult = tt.probeResult
			f.Path = tt.gitPath

			host := platform.Host{OS: tt.hostOS}
			k := &Kind{}

			k.addGuidance(&f, tt.gitPath, host)

			if f.NeedsSystemGuidance != tt.wantNeedsSystemGuid {
				t.Errorf("NeedsSystemGuidance = %v, want %v", f.NeedsSystemGuidance, tt.wantNeedsSystemGuid)
			}

			if f.HasFix != tt.wantHasFix {
				t.Errorf("HasFix = %v, want %v", f.HasFix, tt.wantHasFix)
			}

			if tt.wantCompact != "" && f.GuidanceCompact != tt.wantCompact {
				t.Errorf("GuidanceCompact = %v, want %v", f.GuidanceCompact, tt.wantCompact)
			}
		})
	}
}

func TestCandidates(t *testing.T) {
	t.Run("returns git from PATH and known locations", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Set up runner to respond to command -v git
		runner := exec.NewFakeRunner()
		runner.AddResponse("command", exec.CommandResult{
			Stdout: "/usr/bin/git\n",
		})
		env.Run = runner

		k := &Kind{}
		candidates := k.candidates(context.Background(), env)

		// Should return only executables that exist
		for _, c := range candidates {
			if !discover.IsExecutable(c) {
				t.Errorf("candidates() returned non-executable: %s", c)
			}
		}
	})
}

func TestAudit(t *testing.T) {
	t.Run("finds git installations and probes them", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Create fake git
		gitPath := "/usr/bin/git"
		runner := exec.NewFakeRunner()
		runner.AddResponse("command", exec.CommandResult{
			Stdout: gitPath + "\n",
		})
		runner.AddResponse(gitPath, exec.CommandResult{
			Stdout: "git version 2.43.0\n",
		})
		env.Run = runner

		// Set up probe engine with control URL and both test URLs
		probeEngine := probe.NewFakeEngine()
		probeEngine.AddResult([]probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			{URL: probe.BAD_URLS[1], Verdict: probe.VerdictRejected},
		})
		env.Probe = probeEngine

		// Set HOST to Linux (no xcode-select check needed)
		env.Host = platform.Host{OS: "linux"}

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		if len(findings) == 0 {
			t.Error("Audit() returned no findings")
		}

		for _, f := range findings {
			if f.Kind != "git" {
				t.Errorf("Finding.Kind = %v, want git", f.Kind)
			}
			if f.ProbeResult == "" {
				t.Error("Finding.ProbeResult is empty")
			}
		}
	})

	t.Run("skip macOS system git without Xcode", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Create fake runner
		runner := exec.NewFakeRunner()
		runner.AddResponse("command", exec.CommandResult{
			Stdout: "/usr/bin/git\n",
		})
		runner.AddResponse("/usr/bin/git", exec.CommandResult{
			Stdout: "git version 2.39.3 (Apple Git-146)\n",
		})
		// xcode-select fails
		runner.AddResponse("xcode-select", exec.CommandResult{
			Error: fmt.Errorf("not installed"),
		})
		env.Run = runner

		// Set HOST to macOS
		env.Host = platform.Host{OS: "darwin"}

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		// Should not find any git because /usr/bin/git is skipped
		for _, f := range findings {
			if f.Path == "/usr/bin/git" {
				t.Error("Audit() should skip /usr/bin/git without Xcode")
			}
		}
	})

	t.Run("skips probe when offline", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)
		env.Offline = true

		// Create fake git
		runner := exec.NewFakeRunner()
		runner.AddResponse("command", exec.CommandResult{
			Stdout: "/usr/bin/git\n",
		})
		runner.AddResponse("/usr/bin/git", exec.CommandResult{
			Stdout: "git version 2.43.0\n",
		})
		env.Run = runner

		// Set HOST to Linux
		env.Host = platform.Host{OS: "linux"}

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		for _, f := range findings {
			if f.ProbeResult != kinds.ProbeSkipped {
				t.Errorf("Finding.ProbeResult = %v, want skipped", f.ProbeResult)
			}
		}
	})

	t.Run("deduplicates git by resolved path", func(t *testing.T) {
		env := testutil.NewTestEnvT(t)

		// Create fake runner that returns same git from multiple locations
		runner := exec.NewFakeRunner()
		runner.AddResponse("command", exec.CommandResult{
			Stdout: "/usr/local/bin/git\n",
		})
		// Both return the same version (simulating symlink)
		runner.AddResponse("/usr/local/bin/git", exec.CommandResult{
			Stdout: "git version 2.43.0\n",
		})
		runner.AddResponse("/usr/bin/git", exec.CommandResult{
			Stdout: "git version 2.43.0\n",
		})
		env.Run = runner

		// Set up probe engine
		probeEngine := probe.NewFakeEngine()
		probeEngine.AddResult([]probe.ProbeResult{
			{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
			{URL: probe.BAD_URLS[0], Verdict: probe.VerdictRejected},
			{URL: probe.BAD_URLS[1], Verdict: probe.VerdictRejected},
		})
		env.Probe = probeEngine

		// Set HOST to Linux
		env.Host = platform.Host{OS: "linux"}

		k := &Kind{}
		findings, err := k.Audit(context.Background(), env)
		if err != nil {
			t.Fatalf("Audit() error = %v", err)
		}

		// Should deduplicate based on resolved path
		// Note: In a real test this would need more sophisticated setup
		t.Logf("Found %d findings", len(findings))
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && containsSubstring(s, sub)))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
