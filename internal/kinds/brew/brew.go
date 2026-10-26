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

// Package brew implements the audit Kind and Fixer for Homebrew ca-certificates.
// It checks whether the Homebrew ca-certificates formula is installed and
// whether it trusts the compromised eMudhra intermediate CA chain.
// Homebrew's Python, curl, openssl, and other tools read the bundle at
// $prefix/etc/ca-certificates/cert.pem.
package brew

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

const (
	// kindID is the stable identifier for this Kind.
	kindID = "brew"

	// SectionTitle is the audit_start title for Homebrew ca-certificates, shown in verbose mode.
	SectionTitle = "Homebrew ca-certificates"
)

// Kind implements kinds.Kind and kinds.Fixer for Homebrew ca-certificates.
type Kind struct{}

// New creates a new brew Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "brew".
func (k *Kind) ID() string {
	return kindID
}

// Describe returns a one-line human description.
func (k *Kind) Describe() string {
	return "Homebrew ca-certificates formula"
}

// Applicable reports whether this Kind makes sense on this host. Homebrew
// exists on macOS and Linux, so it applies to both; whether brew is actually
// installed is not a host property (it depends on PATH), so Audit returns no
// findings when it is absent, as the script reports "not installed".
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	if h.OS == "darwin" || h.OS == "linux" {
		return kinds.Applicability{Applies: true}
	}
	return kinds.Applicability{Applies: false, Reason: "Homebrew is supported on macOS and Linux only"}
}

// Audit discovers Homebrew ca-certificates installations and returns findings.
// It ports audit_brew() from the bash script.
//
// Logic:
//  1. Find brew executable and resolve its prefix
//  2. Check if ca-certificates formula is installed (opt/ca-certificates exists)
//  3. Extract version from the symlink/directory name
//  4. Compare version with fixed version 2026-09-25_1 (from advisory)
//  5. Probe the bundle at $prefix/etc/ca-certificates/cert.pem if it exists
//  6. Return findings with status (probe wins over version)
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	// Step 1: Find brew executable
	brewPath := discover.Lookup("brew", env.Path())
	if brewPath == "" {
		// Homebrew not found - this is expected on systems without Homebrew
		return nil, nil
	}

	// Resolve to get the real path (follow symlinks)
	resolvedBrew := discover.Resolve(brewPath)

	// Extract prefix: dirname(dirname(resolved_brew))
	// e.g., /opt/homebrew/bin/brew -> /opt/homebrew
	prefix := filepath.Dir(filepath.Dir(resolvedBrew))

	// Step 2: Check if ca-certificates formula is installed
	// Homebrew installs formulae to $prefix/opt/<formula>
	caCertPath := filepath.Join(prefix, "opt", "ca-certificates")

	// Check if it's a symlink (normal) or a directory (old installation)
	fi, err := os.Lstat(caCertPath)
	if err != nil {
		// ca-certificates formula not installed - this is normal
		return nil, nil
	}

	// Step 3: Extract version from the symlink target or directory name
	var activeVersion string
	if fi.Mode()&os.ModeSymlink != 0 {
		// It's a symlink - read the target
		target, err := os.Readlink(caCertPath)
		if err == nil {
			// Target is typically a relative path like "../Cellar/ca-certificates/2026-09-25_1"
			// Extract the basename
			activeVersion = filepath.Base(target)
		}
	}

	// If we couldn't get it from symlink, use the directory name
	if activeVersion == "" {
		activeVersion = filepath.Base(caCertPath)
	}

	// Step 4: Compare with fixed version from advisory entry "brew-ca-certificates"
	// The advisory entry is "2026-09-25_1" which is a date_revision format, not semver.
	// We need to compare it correctly: normalize both to dotted format.
	//
	// Homebrew formula versions use underscores for revision: 2026-09-25_1
	// For comparison: convert - and _ to dots, resulting in 2026.09.25.1
	// The fixed version from advisory is 2026-09-25_1
	fixedVersionEntry := advisory.GetFixedVersions("brew-ca-certificates")
	if len(fixedVersionEntry) == 0 {
		// This shouldn't happen as the advisory is known
		return nil, fmt.Errorf("no fixed version found for brew-ca-certificates")
	}
	fixedVersion := fixedVersionEntry[0].Version // "2026-09-25_1"

	// Normalize versions for comparison
	// Convert "2026-09-25_1" -> "2026.09.25.1"
	normalizedActive := normalizeHomebrewVersion(activeVersion)
	normalizedFixed := normalizeHomebrewVersion(fixedVersion)

	// Parse and compare: vcmp "$norm" "2026.09.25.1"
	vc := compareHomebrewVersions(normalizedActive, normalizedFixed)

	// Step 5: Probe the bundle file
	bundlePath := filepath.Join(prefix, "etc", "ca-certificates", "cert.pem")
	var probeResult kinds.ProbeResult
	var probeEvidence string

	bundleExists := false
	if fi, err := os.Stat(bundlePath); err == nil && !fi.IsDir() {
		bundleExists = true
	}

	if !bundleExists {
		probeResult = kinds.ProbeSkipped
		probeEvidence = fmt.Sprintf("bundle %s not found", bundlePath)
	} else if env.Offline {
		probeResult = kinds.ProbeSkipped
		probeEvidence = "--no-network"
	} else {
		// Probe the bundle using ProbeCAFile
		// This ports probe_cafile from the bash script
		results, err := probe.ProbeCAFile(ctx, bundlePath)
		if err != nil {
			probeResult = kinds.ProbeInconclusive
			probeEvidence = err.Error()
		} else {
			// Judge combines the probe results
			verdict := probe.NewRealEngine().Judge(results)
			probeResult = kinds.ProbeResult(verdict)
			probeEvidence = describeProbe(verdict)
		}
	}

	// Step 6: Create finding and record facts
	finding := kinds.NewFinding(kindID, "Homebrew ca-certificates")
	finding.Path = caCertPath
	finding.Version = activeVersion
	finding.FixedVersion = fixedVersion

	// Record probe result
	finding.SetProbe(probeResult, probeEvidence)

	// Record version check
	var versionCheck kinds.VersionCheck
	var versionNote string
	switch vc {
	case -1:
		versionCheck = kinds.VersionBehind
		versionNote = "fixed in " + fixedVersion
	case 0, 1:
		versionCheck = kinds.VersionOK
		versionNote = "fixed in " + fixedVersion
	}
	finding.SetVersion(activeVersion, fixedVersion, versionCheck, versionNote)

	// Add guidance if affected or behind
	// The script adds guidance when "[ "${res%%:*}" = trusted ] || [ "$VC" = behind ]"
	if probeResult == kinds.ProbeTrusted || vc == -1 {
		finding.AddGuidance(
			"brew upgrade ca-certificates",
			"brew update && brew upgrade ca-certificates",
			"(Homebrew's Python, curl, openssl and others read this bundle. Old versions linger in the Cellar;",
			" 'brew cleanup ca-certificates' removes them.)",
		)
		// plan_add brew "$prefix"
		finding.HasFix = true
	}

	return []kinds.Finding{finding}, nil
}

// FixOrder implements kinds.Fixer: where this Kind's fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixBrew }

// Plan implements kinds.Fixer. It returns a Fix for each finding that has HasFix=true.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	var fixes []fixrun.Fix
	for _, f := range findings {
		// Plan receives every Kind's findings; act only on this Kind's own.
		if f.Kind != k.ID() {
			continue
		}
		if !f.HasFix {
			continue
		}
		// Path is the opt/ca-certificates directory, so prefix is one level up
		prefix := filepath.Dir(f.Path)
		fixes = append(fixes, &brewFix{
			prefix:   prefix,
			before:   f.Version,
			brewPath: discover.Lookup("brew", env.Path()),
		})
	}
	return fixes, nil
}

// brewFix implements fixrun.Fix for Homebrew ca-certificates.
type brewFix struct {
	prefix   string // Homebrew prefix (e.g., /opt/homebrew)
	before   string // Version before the fix
	brewPath string // Path to brew executable
}

// Kind returns "brew".
func (f *brewFix) Kind() string { return kindID }

// Target returns a description of what is being fixed.
func (f *brewFix) Target() string {
	return "Homebrew ca-certificates"
}

// Run implements fixrun.Fix. It ports fix_brew_store from the bash script:
//   - Say what it will do
//   - Dry-run: print commands and return Skipped
//   - Ask confirmation
//   - Run "brew update" (warn on failure, continue)
//   - Run "brew upgrade ca-certificates"
//   - Verify the installed version and probe
//   - Return Changed on success, Failed on any failure
func (f *brewFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	s.Say("")
	s.Say("%sca-certificates%s", s.Bold("Homebrew "), s.Bold(""))

	// Find the brew binary
	brew := f.brewPath
	if brew == "" {
		brew = "brew" // Fall back to PATH
	}

	// Get the before version (from the symlink)
	before := f.before
	if before == "" {
		// Try to read current version
		link := filepath.Join(f.prefix, "opt", "ca-certificates")
		if target, err := os.Readlink(link); err == nil {
			before = filepath.Base(target)
		}
	}

	s.Say("installed: %s; fixed in 2026-09-25_1 (this is an upgrade, not a trust-store edit)", before)

	// Dry-run: print the plan and return
	if s.DryRun {
		s.Cmd("%s update && %s upgrade ca-certificates", brew, brew)
		return fixrun.Skipped
	}

	// Ask confirmation
	if !s.Confirm("Run 'brew update && brew upgrade ca-certificates'?") {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Run brew update (warn on failure as the script does)
	s.Cmd("%s update", brew)
	result := s.Run.Run(ctx, brew, "update")
	if result.Error != nil || result.ExitCode != 0 {
		s.Warn("brew update reported a problem; continuing")
	}

	// Run brew upgrade ca-certificates
	s.Cmd("%s upgrade ca-certificates", brew)
	result = s.Run.Run(ctx, brew, "upgrade", "ca-certificates")
	if result.Error != nil {
		s.Bad("brew upgrade ca-certificates failed: %v", result.Error)
		return fixrun.Failed
	}

	// Print last few lines of output (as the script does: tail -5)
	output := result.Stdout
	if output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		start := len(lines) - 5
		if start < 0 {
			start = 0
		}
		for _, line := range lines[start:] {
			s.Say("      %s", line)
		}
	}

	// Verify: read the new version from the symlink
	link := filepath.Join(f.prefix, "opt", "ca-certificates")
	after := ""
	if target, err := os.Readlink(link); err == nil {
		after = filepath.Base(target)
	}

	// Probe the bundle
	bundlePath := filepath.Join(f.prefix, "etc", "ca-certificates", "cert.pem")
	v, err := probe.ProbeCAFile(ctx, bundlePath)
	if err != nil {
		s.Bad("probe failed: %v", err)
		return fixrun.Failed
	}

	verdict := probe.NewRealEngine().Judge(v)
	if verdict == probe.VerdictRejected {
		s.OK("verified: Homebrew's bundle (%s) now rejects the compromised chain", after)
		s.Note("Homebrew ca-certificates: %s -> %s (brew cleanup removes the old version)", before, after)
		return fixrun.Changed
	}

	s.Bad("after upgrade, Homebrew's bundle still does not reject the chain (%s); installed: %s", describeProbe(verdict), after)
	return fixrun.Failed
}

// normalizeHomebrewVersion converts Homebrew version format to dotted format for comparison.
// e.g., "2026-09-25_1" -> "2026.09.25.1"
func normalizeHomebrewVersion(v string) string {
	// Replace underscores with dots
	result := strings.ReplaceAll(v, "_", ".")
	// Replace hyphens with dots
	result = strings.ReplaceAll(result, "-", ".")
	return result
}

// compareHomebrewVersions compares two normalized Homebrew versions.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
//
// Homebrew versions are date_revision format: YYYY.MM.DD.revision
// So we compare part by part numerically.
// This ports the script's vcmp logic for this specific format.
func compareHomebrewVersions(a, b string) int {
	// Split into parts
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	// Pad to same length
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		aVal := 0
		if i < len(aParts) {
			_, _ = fmt.Sscanf(aParts[i], "%d", &aVal)
		}
		bVal := 0
		if i < len(bParts) {
			_, _ = fmt.Sscanf(bParts[i], "%d", &bVal)
		}

		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
	}

	return 0
}

// describeProbe returns a human-readable description of the probe verdict.
// Ports the script's describe_probe logic.
func describeProbe(v probe.Verdict) string {
	switch v {
	case probe.VerdictTrusted:
		return "trusted:connected to compromised chain"
	case probe.VerdictRejected:
		return "rejected:certificate rejected"
	case probe.VerdictInconclusive:
		return "inconclusive:control host failed"
	case probe.VerdictSkipped:
		return "skipped"
	default:
		return string(v)
	}
}

// Prefix returns the Homebrew prefix for sysbundle deduplication.
// It resolves via 'brew --prefix' through env.Run, falling back to common paths
// when the directory exists: /opt/homebrew, /usr/local, /home/linuxbrew/.linuxbrew.
//
// This is exported for the sysbundle Kind to call.
func Prefix(env *kinds.Env) string {
	// Try 'brew --prefix' first
	if env.Run != nil {
		result := env.Run.Run(context.Background(), "brew", "--prefix")
		if result.Error == nil && result.Stdout != "" {
			// Clean up output (trim whitespace/newlines)
			prefix := strings.TrimSpace(result.Stdout)
			if _, err := os.Stat(prefix); err == nil {
				return prefix
			}
		}
	}

	// Fallback to common prefixes
	fallbacks := []string{
		"/opt/homebrew",              // macOS Apple Silicon
		"/usr/local",                 // macOS Intel
		"/home/linuxbrew/.linuxbrew", // Linux
	}

	for _, p := range fallbacks {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// AbsentText implements kinds.Absent: why there is no Homebrew section content.
func (k *Kind) AbsentText(env *kinds.Env) string {
	if discover.Lookup("brew", env.Path()) == "" {
		return "Homebrew not found"
	}
	return "ca-certificates formula not installed"
}
