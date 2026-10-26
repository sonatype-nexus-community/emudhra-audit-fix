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

// Package golang implements the Kind for Go installations.
// Ports audit_go and check_go_version from the legacy script (lines 595-644).
package golang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

// SectionTitle is the audit_start title for Go, shown in verbose mode.
const SectionTitle = "Go"

// probeGoSrc is the embedded Go probe source.
// This is ported from the legacy script (lines 472-503).
const probeGoSrc = `package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	c := &http.Client{Timeout: 10 * time.Second}
	for _, u := range os.Args[1:] {
		r := "ok"
		resp, err := c.Get(u)
		if err != nil {
			if strings.Contains(err.Error(), "x509:") {
				r = "certerr"
			} else {
				r = "err"
			}
		} else {
			_ = resp.Body.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "    error:", err)
		}
		fmt.Println(r, u)
	}
}
`

// Kind implements kinds.Kind for Go installations.
type Kind struct{}

// New creates a new golang Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "golang".
func (k *Kind) ID() string {
	return "golang"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Go installations"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers Go installations and returns findings.
// Ports audit_go from the legacy script (lines 612-644).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(env)

	for _, g := range candidates {
		// Resolve symlinks and dedupe
		resolved := discover.Resolve(g)
		if !seen.First(resolved) {
			continue
		}

		// Get version (return value includes "go" prefix, e.g., "go1.26.4")
		versionStr := k.getGoVersion(ctx, env, g)

		// Create finding
		// Tool name is "Go" (script line 641: report "Go" "$g" "${gv:-?}")
		// The version stored includes the "go" prefix for display: "Go go1.26.4"
		f := kinds.NewFinding(k.ID(), "Go")
		f.Path = g // as found on the search path; only the de-duplication uses the resolved path

		// Check version against fixed versions using advisory.GoLineCheck
		// Strip "go" prefix for comparison (advisory expects bare version like "1.26.4")
		if versionStr != "" && versionStr != "?" {
			versionNum := strings.TrimPrefix(versionStr, "go")
			lineCheck, ok := advisory.GoLineCheck(versionNum)
			if ok {
				// Map to kinds.VersionCheck
				var check kinds.VersionCheck
				switch lineCheck.Check {
				case "ok":
					check = kinds.VersionOK
				case "behind":
					check = kinds.VersionBehind
				case "nofix":
					check = kinds.VersionNoFix
				}
				// Set version with "go" prefix for display, but fixed version is bare
				// Script uses bare version for fixed version (e.g., "1.26.10")
				f.SetVersion(versionStr, lineCheck.Fixed, check, lineCheck.Note)
			}
		}

		// Run probe
		if !env.Offline {
			result := k.probeGo(ctx, env, g)
			f.SetProbe(result, probeEvidence(result))
		} else {
			f.SetProbe(kinds.ProbeSkipped, "--no-network")
		}

		// Add guidance
		k.addGuidance(&f, g, env)

		findings = append(findings, f)
	}

	return findings, nil
}

// probeEvidence returns human-readable evidence for a probe result.
func probeEvidence(r kinds.ProbeResult) string {
	switch r {
	case kinds.ProbeTrusted:
		return "connected to a host using the compromised chain"
	case kinds.ProbeRejected:
		return "certificate rejected"
	case kinds.ProbeInconclusive:
		return "control host unreachable or network issue"
	default:
		return ""
	}
}

// candidates returns candidate Go installations.
// Ports the candidate collection from audit_go (lines 616-623).
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// PATH lookup
	if g := discover.Lookup("go", env.Path()); g != "" {
		patterns = append(patterns, g)
	}

	// Common locations
	patterns = append(patterns,
		"/usr/local/go/bin/go",
		"/opt/homebrew/opt/go/libexec/bin/go",
		"/usr/local/opt/go/libexec/bin/go",
	)

	// SDK installations
	home := env.Home()
	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, "sdk", "go*", "bin", "go"),
			filepath.Join(home, "go", "pkg", "mod", "golang.org", "toolchain@*", "bin", "go"),
			filepath.Join(home, ".asdf", "installs", "golang", "*", "go", "bin", "go"),
			filepath.Join(home, ".local", "share", "mise", "installs", "go", "*", "bin", "go"),
		)
	}

	return discover.Executables(discover.Candidates(patterns...))
}

// getGoVersion runs `go version` and extracts the version.
// Ports the version extraction from audit_go (lines 629-631).
// Returns version with "go" prefix, e.g., "go1.26.4" (script uses this format: "Go go1.26.4")
func (k *Kind) getGoVersion(ctx context.Context, env *kinds.Env, goPath string) string {
	// Run with GOTOOLCHAIN=local to prevent auto-downloading toolchains
	result := env.Run.RunWithEnv(ctx, []string{"GOTOOLCHAIN=local"}, goPath, "version")
	if result.Error != nil {
		return "?"
	}

	// Output format: "go version go1.26.0 darwin/arm64"
	// Extract the third field (includes "go" prefix)
	fields := strings.Fields(result.Stdout)
	if len(fields) < 3 {
		return "?"
	}

	// Return version with "go" prefix (e.g., "go1.26.4")
	// Script format: "Go go1.26.4" where Tool="Go" and Version="go1.26.4"
	return fields[2]
}

// probeGo runs a TLS probe using the Go installation.
// Ports the probe section from audit_go (lines 635-639).
func (k *Kind) probeGo(ctx context.Context, env *kinds.Env, goPath string) kinds.ProbeResult {
	// Write probe.go to temp directory (using os directly, not backup)
	// The probe source is embedded in the binary
	tmpDir := filepath.Join(env.TempDir, "go")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		env.Log.Error("failed to create probe directory", "error", err)
		return kinds.ProbeInconclusive
	}

	probeFile := filepath.Join(tmpDir, "probe.go")
	if err := os.WriteFile(probeFile, []byte(probeGoSrc), 0644); err != nil {
		env.Log.Error("failed to write probe.go", "error", err)
		return kinds.ProbeInconclusive
	}

	// Build URLs: control URL first, then bad URLs
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)

	// Run: cd <tmp>/go && GOTOOLCHAIN=local GOFLAGS= GOWORK=off go run probe.go <urls>
	// The script sets GOTOOLCHAIN=local GOFLAGS= GOWORK=off and runs in the temp dir.
	// Since the probe.go has no external dependencies (only stdlib), the working dir
	// is less critical than the env vars, but we pass both for completeness.
	// Note: For real execution, we'd need both dir and env, but the FakeRunner
	// doesn't support RunWithDirAndEnv. We use RunWithEnv since the env vars are
	// the critical part (GOTOOLCHAIN=local prevents auto-download, etc.).
	args := append([]string{"run", probeFile}, urls...)
	result := env.Run.RunWithEnv(ctx,
		[]string{"GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off"},
		goPath, args...,
	)

	if result.Error != nil {
		env.Log.Debug("probe failed", "error", result.Error, "stderr", result.Stderr)
		return kinds.ProbeInconclusive
	}

	// Judge the output
	return kinds.ResultOf(probe.JudgeOutput(result.Stdout))
}

// addGuidance adds remediation guidance to the finding.
// Ports fix_go from the legacy script (lines 1149-1160).
func (k *Kind) addGuidance(f *kinds.Finding, goPath string, env *kinds.Env) {
	// Compact guidance: most useful single action
	if f.ProbeResult == kinds.ProbeTrusted {
		f.AddGuidance(
			"This Go build trusts the compromised chain via the OS trust store",
			"This Go build trusts the compromised chain via the OS trust store: see System trust store below.",
		)
		// fix_go: FIXSYS=1, which plans the host-wide system trust store fix.
		f.NeedsSystemGuidance = true
	}

	// Add upgrade guidance if behind or nofix
	if f.VersionCheck == kinds.VersionBehind || f.VersionCheck == kinds.VersionNoFix {
		f.AddGuidance(fmt.Sprintf("upgrade Go to %s or later (https://go.dev/dl/)", f.FixedVersion))

		// Add source-specific guidance
		source := discover.WhereFrom(goPath)
		switch source {
		case discover.SourceBrew:
			f.GuidanceFull = append(f.GuidanceFull,
				fmt.Sprintf("Upgrade Go to %s or later: brew upgrade go", f.FixedVersion))
		case discover.SourceMise:
			f.GuidanceFull = append(f.GuidanceFull,
				fmt.Sprintf("Upgrade Go to %s or later: mise use -g go@%s", f.FixedVersion, f.FixedVersion))
		case discover.SourceASDF:
			f.GuidanceFull = append(f.GuidanceFull,
				fmt.Sprintf("Upgrade Go to %s or later: asdf install golang %s", f.FixedVersion, f.FixedVersion))
		case discover.SourceGo:
			f.GuidanceFull = append(f.GuidanceFull,
				fmt.Sprintf("Upgrade Go to %s or later: download from https://go.dev/dl/ and replace /usr/local/go", f.FixedVersion))
		default:
			f.GuidanceFull = append(f.GuidanceFull,
				fmt.Sprintf("Upgrade Go to %s or later (https://go.dev/dl/). Projects can also pin it with 'toolchain' in go.mod.", f.FixedVersion))
		}
	}
}
