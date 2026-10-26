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

// Package rustup implements the Kind for rustup installations.
// Ports audit_simple "rustup", rustup_install_method, rustup_upgrade_cmd, and fix_rustup
// from the legacy script (lines 1570-1589, 3027-3061, 3225).
package rustup

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// Kind implements kinds.Kind and kinds.Fixer for rustup installations.
type Kind struct{}

// New creates a new rustup Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "rustup".
func (k *Kind) ID() string {
	return "rustup"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Rustup (Rust toolchain installer)"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers rustup installations and returns findings.
// Ports audit_simple "rustup" from the legacy script (line 3225).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	// Get fixed version from advisory
	fixedVersions := advisory.GetFixedVersions("rustup")
	if len(fixedVersions) == 0 {
		return nil, fmt.Errorf("no fixed version found for rustup")
	}
	fixedVersion := fixedVersions[0].Version // "1.29.2"

	// Build candidate list
	candidates := k.candidates(env)

	// Deduplicate by resolved path
	seen := &discover.Seen{}

	for _, path := range candidates {
		// Resolve symlinks and deduplicate
		resolved := discover.Resolve(path)
		key := "rustup:" + resolved
		if !seen.First(key) {
			continue
		}

		// Get version via --version
		result := env.Run.Run(ctx, path, "--version")
		if result.Error != nil || result.ExitCode != 0 {
			// Cannot determine version
			f := kinds.NewFinding(k.ID(), "rustup")
			f.Path = path
			f.SetProbe(kinds.ProbeSkipped, fmt.Sprintf("version check failed: %v", result.Error))
			f.AddGuidance("(no specific guidance - see https://emudhra.we-have-a-problem.com/)")
			findings = append(findings, f)
			continue
		}

		// Extract version: "rustup 1.28.0 (abc123 2026-01-01)"
		ver := extractRustupVersion(result.Stdout)
		if ver == "" {
			ver = "unknown"
		}

		// Compare with fixed version
		v := version.Parse(ver)
		fixed := version.Parse(fixedVersion)

		f := kinds.NewFinding(k.ID(), "rustup")
		f.Path = path

		if v.GE(fixed) {
			// Version is fixed or newer
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionOK, "fixed in "+fixedVersion)
		} else {
			// Version is behind
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionBehind, "fixed in "+fixedVersion)

			// Add guidance - check install method first
			method := k.installMethod(path, env)
			cmd := k.upgradeCmd(method)
			f.AddGuidance(cmd+"   (or: brew upgrade rustup if installed via Homebrew)",
				"Upgrade rustup to "+fixedVersion+" or later: "+cmd,
			)
			f.HasFix = true
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// FixOrder implements kinds.Fixer: where this Kind's fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixRustup }

// Plan returns fixes for findings that are behind the fixed version and have an official install.
// Ports the logic from fix_rustup (lines 3027-3061).
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	var fixes []fixrun.Fix

	for _, f := range findings {
		if f.Kind != k.ID() {
			continue
		}
		// Only schedule a fix if version is behind and we can fix it
		if f.VersionCheck != kinds.VersionBehind {
			continue
		}
		if f.Path == "" {
			continue
		}

		// Check install method
		method := k.installMethod(f.Path, env)

		// Only schedule fix for official installs
		if method == "official" {
			fixes = append(fixes, &rustupFix{
				path:         f.Path,
				oldVersion:   f.Version,
				fixedVersion: f.FixedVersion,
			})
		}
	}

	return fixes, nil
}

// installMethod determines how rustup was installed.
// Ports rustup_install_method from the legacy script (lines 1570-1579).
func (k *Kind) installMethod(rustupPath string, env *kinds.Env) string {
	// Resolve the path
	resolved := discover.Resolve(rustupPath)

	// Get CARGO_HOME (default: ~/.cargo)
	cargoHome := env.Getenv("CARGO_HOME")
	if cargoHome == "" {
		cargoHome = filepath.Join(env.Home(), ".cargo")
	}

	// Check for Homebrew patterns (line 1574)
	if strings.Contains(rustupPath+resolved, "/Cellar/") ||
		strings.HasPrefix(rustupPath, "/opt/homebrew/") ||
		strings.HasPrefix(rustupPath, "/usr/local/opt/") ||
		strings.Contains(rustupPath, "/.linuxbrew/") {
		return "brew"
	}

	// Check for system package manager paths (line 1575)
	if strings.HasPrefix(rustupPath, "/usr/bin/") ||
		strings.HasPrefix(rustupPath, "/bin/") ||
		strings.HasPrefix(rustupPath, "/usr/sbin/") ||
		strings.HasPrefix(rustupPath, "/usr/local/bin/") ||
		strings.HasPrefix(rustupPath, "/snap/") {
		return "system"
	}

	// Check for official rustup-init install (line 1577)
	// Official installs live in $CARGO_HOME/bin/
	if strings.HasPrefix(rustupPath, filepath.Join(cargoHome, "bin")) {
		return "official"
	}

	return "unknown"
}

// upgradeCmd returns the upgrade command for the install method.
// Ports rustup_upgrade_cmd from the legacy script (lines 1582-1589).
func (k *Kind) upgradeCmd(method string) string {
	switch method {
	case "official":
		return "rustup self update"
	case "brew":
		return "brew upgrade rustup"
	case "system":
		return "your package manager (apt/dnf/pacman/apk upgrade rustup)"
	default:
		return "rustup self update   (official install), or your package manager: brew upgrade rustup"
	}
}

// candidates returns candidate rustup installations.
// Ports the candidate list from audit_simple (line 3225).
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// CARGO_HOME/bin/rustup (primary location for official installs)
	cargoHome := env.Getenv("CARGO_HOME")
	if cargoHome == "" {
		cargoHome = filepath.Join(env.Home(), ".cargo")
	}
	patterns = append(patterns, filepath.Join(cargoHome, "bin", "rustup"))

	// PATH lookup
	if p := discover.Lookup("rustup", env.Path()); p != "" {
		patterns = append(patterns, p)
	}

	return discover.Executables(discover.Candidates(patterns...))
}

// extractRustupVersion extracts the version from rustup --version output.
// Output format: "rustup 1.28.0 (abc123 2026-01-01)"
// We extract the second field (version number).
func extractRustupVersion(output string) string {
	fields := strings.Fields(output)
	if len(fields) >= 2 && fields[0] == "rustup" {
		return fields[1]
	}
	return ""
}

// rustupFix implements fixrun.Fix for rustup self update.
type rustupFix struct {
	path         string
	oldVersion   string
	fixedVersion string
}

// Kind returns the Kind ID.
func (f *rustupFix) Kind() string { return "rustup" }

// Target returns the path being fixed.
func (f *rustupFix) Target() string { return f.path }

// Run executes the rustup self update.
// Ports fix_rustup from the legacy script (lines 3027-3061).
func (f *rustupFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	// Say what we're doing
	s.Say("%s  %s  (%s, install method: official)", s.Bold("rustup"), f.path, f.oldVersion)

	// Check if this is a dry run
	if s.DryRun {
		s.Cmd("%s self update", f.path)
		s.Say("[dry-run] would then re-read 'rustup --version' and compare it with %s; nothing is changed now", f.fixedVersion)
		return fixrun.Skipped
	}

	// Confirm
	if !s.Confirm(fmt.Sprintf("Upgrade rustup with '%s self update'?", f.path)) {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Backup the binary
	bak, err := s.Backup(ctx, f.path)
	if err != nil {
		s.Bad("could not back up %s - nothing was changed", f.path)
		return fixrun.Failed
	}

	// Run the update
	s.Cmd("%s self update", f.path)
	result := s.Run.RunWithInput(ctx, "", f.path, "self", "update")
	if result.Stdout != "" {
		// Print output (indented, last 6 lines as the script does)
		lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
		start := 0
		if len(lines) > 6 {
			start = len(lines) - 6
		}
		for _, line := range lines[start:] {
			s.Say("      %s", line)
		}
	}

	// Verify: read the new version
	newVer := f.getRustupVersion(ctx, s.Run)
	if newVer == "" {
		// rustup no longer reports a version - restore the backup
		s.Bad("rustup no longer reports a version - restoring the previous binary. If it is still broken, reinstall with rustup-init (https://rustup.rs)")
		if err := s.Restore(ctx, bak, f.path); err != nil {
			s.Warn("failed to restore backup: %v", err)
		}
		return fixrun.Failed
	}

	// Check if the version is now fixed or newer
	v := version.Parse(newVer)
	fixed := version.Parse(f.fixedVersion)
	if v.GE(fixed) {
		s.OK("rustup --version now reports %s (fixed in %s). This is a version check, not a TLS probe.", newVer, f.fixedVersion)
		s.Say("Note: this upgrades rustup only. Rust toolchains are not updated (rustup update), and Rust projects still need")
		s.Say("rustls-webpki >= 0.103.16 and webpki-roots >= 1.0.10 in Cargo.lock (cargo update -p rustls-webpki -p webpki-roots).")
		return fixrun.Changed
	}

	// Version is still behind
	s.Bad("rustup reports %s, still behind %s (the update may not have happened) - the binary still works", newVer, f.fixedVersion)
	return fixrun.Failed
}

// getRustupVersion gets the current rustup version.
func (f *rustupFix) getRustupVersion(ctx context.Context, runner exec.Runner) string {
	result := runner.Run(ctx, f.path, "--version")
	if result.Error != nil || result.ExitCode != 0 {
		return ""
	}
	return extractRustupVersion(result.Stdout)
}
