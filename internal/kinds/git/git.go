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

// Package git implements the git Kind: audit for git installations.
// Ports audit_git(), git_probe_all(), fix_git() (guidance only) from the bash script.
package git

import (
	"context"
	"fmt"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

// SectionTitle is the audit_start title for git, shown in verbose mode.
const SectionTitle = "git"

// Kind implements kinds.Kind for git installations.
type Kind struct{}

// New creates a new git Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "git".
func (k *Kind) ID() string {
	return "git"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "git version control"
}

// Applicable returns true on both macOS and Linux (git exists on both).
// Note: macOS /usr/bin/git is a stub unless xcode-select -p succeeds.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers git installations and returns findings.
// Ports audit_git() from legacy/emudhra-audit-fix.sh lines 1788-1820.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(ctx, env)

	for _, path := range candidates {
		// Resolve symlinks and deduplicate
		resolved := discover.Resolve(path)
		if !seen.First(resolved) {
			continue
		}

		// macOS /usr/bin/git is a stub unless xcode-select -p succeeds (line 1794)
		if path == "/usr/bin/git" && env.Host.OS == "darwin" {
			if !k.xcodeToolsInstalled(ctx, env.Run) {
				continue
			}
		}

		// Get version (line 1797)
		versionStr := k.getVersion(ctx, env, path)

		// Build finding
		f := kinds.NewFinding(k.ID(), "git")
		f.Path = resolved
		f.Version = versionStr

		// No fixed git version; depends on CA bundle
		// From script: VC=na VN="no fixed git version; depends on the CA bundle in use"
		f.VersionCheck = kinds.VersionNA
		f.VersionNote = "no fixed git version; depends on the CA bundle in use"

		// Run TLS probe
		if !env.Offline {
			results, err := env.Probe.Probe(ctx, probe.BAD_URLS, probe.CONTROL_URL)
			if err != nil {
				f.SetProbe(kinds.ProbeInconclusive, err.Error())
			} else {
				verdict := env.Probe.Judge(results)
				f.SetProbe(kinds.ResultOf(verdict), probeEvidence(verdict))
			}
		} else {
			f.SetProbe(kinds.ProbeSkipped, "--no-network")
		}

		// Get environment notes and git config (lines 1806-1812)
		envNotes := k.envNotes(ctx, env, path)
		if envNotes != "" {
			f.Notes = envNotes
		}

		// Add guidance (ports fix_git lines 1771-1786)
		k.addGuidance(&f, path, env.Host)

		findings = append(findings, f)
	}

	return findings, nil
}

// candidates returns potential git installations.
// Ports lines 1815-1817 from the script.
// MUST report every git (command -v git plus known paths) deduped by resolved path,
// not just the first on PATH.
func (k *Kind) candidates(ctx context.Context, env *kinds.Env) []string {
	var patterns []string

	// Check command -v output (from PATH) - this is the primary discovery method
	// The script uses: command -v git 2>/dev/null
	result := env.Run.Run(ctx, "command", "-v", "git")
	if result.Error == nil {
		p := strings.TrimSpace(result.Stdout)
		if p != "" && discover.IsExecutable(p) {
			patterns = append(patterns, p)
		}
	}

	// Common locations (from line 1816)
	// These are checked in addition to PATH, then deduped by resolved path
	patterns = append(patterns,
		"/opt/homebrew/bin/git",
		"/usr/local/bin/git",
		"/usr/bin/git",
	)

	return discover.Executables(discover.Candidates(patterns...))
}

// xcodeToolsInstalled checks if Xcode Command Line Tools is installed.
// Ports line 1794 from the script.
func (k *Kind) xcodeToolsInstalled(ctx context.Context, runner exec.Runner) bool {
	result := runner.Run(ctx, "xcode-select", "-p")
	return result.Error == nil
}

// getVersion extracts version from git --version output.
// Ports line 1797 from the script.
func (k *Kind) getVersion(ctx context.Context, env *kinds.Env, gitPath string) string {
	result := env.Run.Run(ctx, gitPath, "--version")
	if result.Error != nil {
		return "?"
	}

	// Output: "git version 2.43.0"
	parts := strings.Fields(result.Stdout)
	if len(parts) >= 3 && parts[0] == "git" && parts[1] == "version" {
		return parts[2]
	}
	return "?"
}

// envNotes returns environment variable notes and git config.
// Ports lines 1806-1812 from the script.
func (k *Kind) envNotes(ctx context.Context, env *kinds.Env, gitPath string) string {
	var notes []string

	// Check environment variables (line 1806)
	// GIT_SSL_CAINFO, GIT_SSL_CAPATH, SSL_CERT_FILE
	vars := []string{"GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "SSL_CERT_FILE"}
	for _, v := range vars {
		if val := env.Getenv(v); val != "" {
			notes = append(notes, fmt.Sprintf("%s=%s", v, val))
		}
	}

	// Check http.sslCAInfo (lines 1807-1809)
	// Run: git config --get http.sslCAInfo
	sslCAInfoResult := env.Run.RunWithDir(ctx, env.TempDir, gitPath, "config", "--get", "http.sslCAInfo")
	sslCAInfo := strings.TrimSpace(sslCAInfoResult.Stdout)
	if sslCAInfo != "" {
		notes = append(notes, fmt.Sprintf("http.sslCAInfo=%s", sslCAInfo))
	}

	// Check http.sslVerify (lines 1810-1812)
	// Run: git config --get http.sslVerify
	sslVerifyResult := env.Run.RunWithDir(ctx, env.TempDir, gitPath, "config", "--get", "http.sslVerify")
	sslVerify := strings.TrimSpace(sslVerifyResult.Stdout)
	if sslVerify == "false" {
		notes = append(notes, "http.sslVerify=false - git skips certificate checks")
	}

	// Check for warning variables (from audit_env)
	if val := env.Getenv("GIT_SSL_NO_VERIFY"); val != "" {
		notes = append(notes, "WARNING: GIT_SSL_NO_VERIFY is set: git skips certificate checks")
	}
	if env.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		notes = append(notes, "WARNING: NODE_TLS_REJECT_UNAUTHORIZED=0: Node skips certificate checks")
	}
	if env.Getenv("PYTHONHTTPSVERIFY") == "0" {
		notes = append(notes, "WARNING: PYTHONHTTPSVERIFY=0 is set (ignored by isolated probes, but affects your own Python scripts)")
	}

	if len(notes) == 0 {
		return ""
	}

	return "    note: " + strings.Join(notes, "\n    note: ")
}

// probeEvidence returns human-readable evidence for a probe verdict.
func probeEvidence(v probe.Verdict) string {
	switch v {
	case probe.VerdictTrusted:
		return "connected to a host using the compromised chain"
	case probe.VerdictRejected:
		return "certificate rejected"
	case probe.VerdictSkipped:
		return "skipped (--no-network)"
	default:
		return "control host unreachable or network issue"
	}
}

// addGuidance adds remediation guidance text.
// Ports fix_git() lines 1771-1786 from the script.
func (k *Kind) addGuidance(f *kinds.Finding, gitPath string, h platform.Host) {
	// Only add guidance if affected (line 1772: [ "${2%%:*}" = trusted ])
	if f.ProbeResult != kinds.ProbeTrusted {
		return
	}

	source := discover.WhereFrom(gitPath)

	switch source {
	case discover.SourceBrew:
		// Compact: "brew upgrade git ca-certificates"
		// Full: "brew update && brew upgrade git ca-certificates"
		f.AddGuidance(
			"brew upgrade git ca-certificates",
			"brew update && brew upgrade git ca-certificates",
		)
		f.HasFix = true
	default:
		// Compact: "patch the system CA bundle (or use Homebrew's git)"
		// Full: multi-line guidance from lines 1777-1784
		if gitPath == "/usr/bin/git" && h.OS == "darwin" {
			f.AddGuidance(
				"patch the system CA bundle (or use Homebrew's git)",
				"Apple's git reads /etc/ssl/cert.pem and does not check revocation: see System trust store below,",
				"or use Homebrew's git: brew install git && brew upgrade ca-certificates",
			)
		} else {
			f.AddGuidance(
				"patch the system CA bundle (or use Homebrew's git)",
				"git uses the OS/curl CA bundle (http.sslCAInfo or GIT_SSL_CAINFO if set): update ca-certificates,",
				"or see System trust store below.",
			)
		}
		// Set NeedsSystemGuidance (the script's FIXSYS=1)
		f.NeedsSystemGuidance = true
	}
}
