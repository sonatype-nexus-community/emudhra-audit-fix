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

// Package deno implements the Kind for Deno installations.
// Ports audit_deno from the legacy script (lines 1462-1479).
package deno

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
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// SectionTitle is the audit_start title for Deno, shown in verbose mode.
const SectionTitle = "Deno"

// probeJSSrc is the embedded JavaScript probe source for Deno.
// This is ported from the legacy script (lines 1290-1302).
const probeJSSrc = `for (const u of Deno.args) {
  try {
    const r = await fetch(u);
    await r.body?.cancel();
    console.log("ok", u);
  } catch (e) {
    const m = String(e);
    console.error("    error: " + m);
    console.log(/certificate|UnknownIssuer|Revoked|invalid peer/i.test(m) ? "certerr" : "err", u);
  }
}
`

// Kind implements kinds.Kind for Deno installations.
type Kind struct{}

// New creates a new deno Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "deno".
func (k *Kind) ID() string {
	return "deno"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Deno installations"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers Deno installations and returns findings.
// Ports audit_deno from the legacy script (lines 1462-1479).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(env)

	for _, d := range candidates {
		// Resolve symlinks and dedupe
		resolved := discover.Resolve(d)
		if !seen.First(resolved) {
			continue
		}

		// Get version
		versionStr := k.getDenoVersion(ctx, env, d)

		// Create finding
		f := kinds.NewFinding(k.ID(), "Deno")
		f.Path = resolved

		// Check version against fixed version (2.9.8)
		fixedVersions := advisory.GetFixedVersions("deno")
		if len(fixedVersions) > 0 && versionStr != "" && versionStr != "?" {
			fixv := fixedVersions[0].Version
			vParsed := version.Parse(versionStr)
			fixParsed := version.Parse(fixv)
			if vParsed.GE(fixParsed) {
				f.SetVersion(versionStr, fixv, kinds.VersionOK, "fixed in "+fixv)
			} else {
				f.SetVersion(versionStr, fixv, kinds.VersionBehind, "fixed in "+fixv)
			}
		}

		// Run probe
		if !env.Offline {
			result := k.probeDeno(ctx, env, d)
			f.SetProbe(result, probeEvidence(result))
		} else {
			f.SetProbe(kinds.ProbeSkipped, "--no-network")
		}

		// Add guidance
		k.addGuidance(&f, d)

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

// candidates returns candidate Deno installations.
// Ports the candidate collection from audit_deno (lines 1475-1476).
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// PATH lookup
	if d := discover.Lookup("deno", env.Path()); d != "" {
		patterns = append(patterns, d)
	}

	// Common locations
	patterns = append(patterns,
		"/opt/homebrew/bin/deno",
		"/usr/local/bin/deno",
	)

	// Home directory installations
	home := env.Home()
	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".deno", "bin", "deno"),
		)
	}

	return discover.Executables(discover.Candidates(patterns...))
}

// getDenoVersion runs `deno --version` and extracts the version.
// Ports the version extraction from audit_deno (line 1469).
func (k *Kind) getDenoVersion(ctx context.Context, env *kinds.Env, denoPath string) string {
	result := env.Run.RunWithInput(ctx, "", denoPath, "--version")
	if result.Error != nil {
		return "?"
	}

	// Output format:
	// deno 2.0.0 (stable, release, aarch64-apple-darwin)
	// v8 12.7.224.13
	// typescript 5.4.5
	//
	// We need the first line, second field
	lines := strings.Split(result.Stdout, "\n")
	if len(lines) < 1 {
		return "?"
	}

	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return "?"
	}

	return fields[1]
}

// probeDeno runs a TLS probe using the Deno installation.
// Ports the probe section from audit_deno (line 1471).
func (k *Kind) probeDeno(ctx context.Context, env *kinds.Env, denoPath string) kinds.ProbeResult {
	// Write probe.js to temp directory
	probeFile := filepath.Join(env.TempDir, "deno_probe.js")
	if err := os.WriteFile(probeFile, []byte(probeJSSrc), 0644); err != nil {
		env.Log.Error("failed to write deno_probe.js", "error", err)
		return kinds.ProbeInconclusive
	}

	// Build URLs: control URL first, then bad URLs
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)

	// Run: deno run --no-prompt --allow-net probe.js <urls>
	args := append([]string{"run", "--no-prompt", "--allow-net", probeFile}, urls...)
	result := env.Run.RunWithInput(ctx, "", denoPath, args...)

	if result.Error != nil {
		env.Log.Debug("probe failed", "error", result.Error, "stderr", result.Stderr)
		return kinds.ProbeInconclusive
	}

	// Judge the output
	return kinds.ResultOf(probe.JudgeOutput(result.Stdout))
}

// addGuidance adds remediation guidance to the finding.
// Ports fix from audit_deno (lines 1472-1473).
func (k *Kind) addGuidance(f *kinds.Finding, denoPath string) {
	// Add upgrade guidance if affected or behind
	if f.ProbeResult == kinds.ProbeTrusted || f.VersionCheck == kinds.VersionBehind {
		fixv := f.FixedVersion
		if fixv == "" {
			fixv = "2.9.8" // Default fixed version for Deno
		}
		f.AddGuidance(
			fmt.Sprintf("Upgrade Deno to %s or later", fixv),
			fmt.Sprintf("Upgrade Deno to %s or later: deno upgrade   (or brew upgrade deno)", fixv),
		)
	}
}
