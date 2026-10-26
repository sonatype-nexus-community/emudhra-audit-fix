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

// Package bun implements the Kind for Bun installations.
// Ports audit_bun from the legacy script (lines 1481-1500).
// Note: The advisory lists no fixed Bun release yet (pending).
package bun

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

// SectionTitle is the audit_start title for Bun, shown in verbose mode.
const SectionTitle = "Bun"

// probeJSSrc is the embedded JavaScript probe source for Bun.
// This is ported from the legacy script (lines 1304-1317).
const probeJSSrc = `const urls = process.argv.slice(2);
for (const u of urls) {
  try {
    const r = await fetch(u);
    await r.arrayBuffer();
    console.log("ok", u);
  } catch (e) {
    const m = String(e) + " " + (e && e.code ? e.code : "");
    console.error("    error: " + m);
    console.log(/CERT|certificate|UNABLE_TO|SELF_SIGNED/i.test(m) ? "certerr" : "err", u);
  }
}
`

// Kind implements kinds.Kind for Bun installations.
type Kind struct{}

// New creates a new bun Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "bun".
func (k *Kind) ID() string {
	return "bun"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Bun installations"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers Bun installations and returns findings.
// Ports audit_bun from the legacy script (lines 1481-1500).
// Note: There is no fixed version for Bun yet (pending).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(env)

	for _, b := range candidates {
		// Resolve symlinks and dedupe
		resolved := discover.Resolve(b)
		if !seen.First(resolved) {
			continue
		}

		// Get version
		versionStr := k.getBunVersion(ctx, env, b)

		// Create finding
		f := kinds.NewFinding(k.ID(), "Bun")
		f.Path = resolved
		f.Version = versionStr
		// Bun has no fixed version yet (pending), so version check is na
		// The script uses: VC=na VN="no fixed release yet (listed as pending)"
		f.VersionCheck = kinds.VersionNA
		f.VersionNote = "no fixed release yet (listed as pending)"

		// Run probe (Bun has no fixed version, so only probe matters)
		if !env.Offline {
			result := k.probeBun(ctx, env, b)
			f.SetProbe(result, probeEvidence(result))
		} else {
			f.SetProbe(kinds.ProbeSkipped, "--no-network")
		}

		// Add guidance
		k.addGuidance(&f, b)

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

// candidates returns candidate Bun installations.
// Ports the candidate collection from audit_bun (lines 1495-1496).
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// PATH lookup
	if b := discover.Lookup("bun", env.Path()); b != "" {
		patterns = append(patterns, b)
	}

	// Common locations
	patterns = append(patterns,
		"/opt/homebrew/bin/bun",
		"/usr/local/bin/bun",
	)

	// Home directory installations
	home := env.Home()
	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".bun", "bin", "bun"),
		)
	}

	return discover.Executables(discover.Candidates(patterns...))
}

// getBunVersion runs `bun --version` and extracts the version.
// Ports the version extraction from audit_bun (line 1488).
func (k *Kind) getBunVersion(ctx context.Context, env *kinds.Env, bunPath string) string {
	result := env.Run.RunWithInput(ctx, "", bunPath, "--version")
	if result.Error != nil {
		return "?"
	}

	// Output format: just the version string
	v := strings.TrimSpace(result.Stdout)
	if v == "" {
		return "?"
	}

	return v
}

// probeBun runs a TLS probe using the Bun installation.
// Ports the probe section from audit_bun (line 1489).
func (k *Kind) probeBun(ctx context.Context, env *kinds.Env, bunPath string) kinds.ProbeResult {
	// Write probe.js to temp directory
	probeFile := filepath.Join(env.TempDir, "bun_probe.js")
	if err := os.WriteFile(probeFile, []byte(probeJSSrc), 0644); err != nil {
		env.Log.Error("failed to write bun_probe.js", "error", err)
		return kinds.ProbeInconclusive
	}

	// Build URLs: control URL first, then bad URLs
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)

	// Run: bun run probe.js <urls>
	args := append([]string{"run", probeFile}, urls...)
	result := env.Run.RunWithInput(ctx, "", bunPath, args...)

	if result.Error != nil {
		env.Log.Debug("probe failed", "error", result.Error, "stderr", result.Stderr)
		return kinds.ProbeInconclusive
	}

	// Judge the output
	return kinds.ResultOf(probe.JudgeOutput(result.Stdout))
}

// addGuidance adds remediation guidance to the finding.
// Ports fix from audit_bun (lines 1491-1493).
func (k *Kind) addGuidance(f *kinds.Finding, bunPath string) {
	// Bun has no fixed release yet
	if f.ProbeResult == kinds.ProbeTrusted {
		f.AddGuidance(
			"No fixed Bun release yet (pending) - watch https://emudhra.we-have-a-problem.com/",
			"The page lists no fixed Bun release yet (pending). Watch https://emudhra.we-have-a-problem.com/",
			"and upgrade as soon as one ships: bun upgrade. Until then avoid Bun for sensitive outbound TLS.",
		)
	}
}
