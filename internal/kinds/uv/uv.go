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

// Package uv implements the audit and fix Kind for the uv binary itself.
// It ports audit_simple("uv"), uv_install_method, uv_upgrade_cmd, and fix_uv
// from the legacy script (lines 3226, 1537-1566, 2650-2683).
//
// uv is installed by several methods:
//   - standalone installer (uv self update works)
//   - Homebrew (brew upgrade uv)
//   - pipx (pipx upgrade uv)
//   - pip in a virtual environment
//   - cargo (cargo install --locked --force uv)
//   - mise (mise use -g uv@latest)
//   - asdf
//
// Only the standalone installer can use `uv self update`. The others
// require their own package manager. This Kind guides the user to the right
// command for their installation method and runs `self update` only when
// appropriate.
//
// The uvpython and uvtools Kinds (separate packages) share the helpers in internal/uvenv.
package uv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

const (
	// kindID is the stable identifier for this Kind.
	kindID = "uv"
	// fixedVersion is the minimum fixed version for uv.
	fixedVersion = "0.13.4"
)

// Kind implements kinds.Kind and kinds.Fixer for the uv binary.
type Kind struct{}

// New creates a new uv Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "uv".
func (k *Kind) ID() string {
	return kindID
}

// Describe returns a one-line human description.
func (k *Kind) Describe() string {
	return "uv package manager (standalone installer only)"
}

// Applicable reports that uv applies on all platforms.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// Audit discovers uv installations and returns findings.
// This ports audit_simple("uv") from the bash script (line 3226).
//
// Logic:
//  1. Candidate paths: $HOME/.local/bin/uv, $HOME/.cargo/bin/uv, PATH lookup
//  2. Deduplicate by resolved path
//  3. Get version via `uv --version`
//  4. Compare with fixed version 0.13.4
//  5. Set HasFix = true when install method is standalone (can self update)
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	// Build candidate list (script line 3226)
	candidates := discover.Candidates(
		filepath.Join(env.Home(), ".local/bin/uv"),
		filepath.Join(env.Home(), ".cargo/bin/uv"),
	)

	// Add PATH lookup
	if p := discover.Lookup("uv", env.Path()); p != "" {
		candidates = append(candidates, p)
	}

	// Filter to executables only
	candidates = discover.Executables(candidates)

	if len(candidates) == 0 {
		return nil, nil
	}

	var findings []kinds.Finding

	// Deduplicate by resolved path
	seen := &discover.Seen{}

	for _, path := range candidates {
		// Resolve symlinks and deduplicate
		resolved := discover.Resolve(path)
		key := kindID + ":" + resolved
		if !seen.First(key) {
			continue
		}

		// Get version via --version
		result := env.Run.Run(ctx, path, "--version")
		if result.Error != nil || result.ExitCode != 0 {
			// Cannot determine version
			f := kinds.NewFinding(kindID, "uv")
			f.Path = path
			f.SetProbe(kinds.ProbeSkipped, fmt.Sprintf("version check failed: %v", result.Error))
			f.AddGuidance("(no specific guidance - see https://emudhra.we-have-a-problem.com/)")
			findings = append(findings, f)
			continue
		}

		// Extract version (script: version_of, line 1592-1598)
		// uv outputs: "uv 0.13.4" (or similar)
		ver := discover.ExtractVersion(result.Stdout)
		if ver == "" {
			ver = "unknown"
		}

		// Compare with fixed version
		v := version.Parse(ver)
		fixed := version.Parse(fixedVersion)

		f := kinds.NewFinding(kindID, "uv")
		f.Path = path

		if v.GE(fixed) {
			// Version is fixed or newer
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionOK, "fixed in "+fixedVersion)
		} else {
			// Version is behind
			f.SetProbe(kinds.ProbeSkipped, kinds.VersionOnlyProbeReason)
			f.SetVersion(ver, fixedVersion, kinds.VersionBehind, "fixed in "+fixedVersion)

			// Determine install method and guidance
			installMethod := installMethod(path, env)
			cmd := upgradeCmd(installMethod)

			if installMethod == "standalone" {
				// Can self update - this finding has an automated fix
				f.HasFix = true
				f.AddGuidance(
					"uv self update   (or: brew upgrade uv / pipx upgrade uv)",
					"Install method: "+installMethod,
					"Run: "+cmd,
				)
			} else {
				// Other install methods require manual intervention
				f.AddGuidance(
					"uv self update   (standalone install), or your package manager: brew upgrade uv / pipx upgrade uv",
					"Install method: "+installMethod,
					"Run: "+cmd,
				)
			}
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// FixOrder implements kinds.Fixer: where this Kind's fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixUV }

// Plan returns fixes for findings that can be fixed (standalone installs only).
// This ports the planning part of fix_uv (lines 2650-2683).
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

		// Double-check install method (defensive)
		method := installMethod(f.Path, env)
		if method != "standalone" {
			continue
		}

		fixes = append(fixes, &uvFix{
			path:     f.Path,
			oldVer:   f.Version,
			method:   method,
			fixedVer: fixedVersion,
		})
	}

	return fixes, nil
}

// installMethod determines how uv was installed.
// This ports uv_install_method from the bash script (lines 1537-1552).
// Returns: standalone, brew, pipx, pip, cargo, mise, asdf, or unknown.
func installMethod(uvBin string, env *kinds.Env) string {
	// Resolve symlinks
	resolved := discover.Resolve(uvBin)
	binDir := filepath.Dir(uvBin)

	// Check path patterns for mise and asdf (script lines 1541-1542)
	switch {
	case strings.Contains(uvBin, "/mise/") || strings.Contains(uvBin, "/.mise/"):
		return "mise"
	case strings.Contains(uvBin, "/.asdf/"):
		return "asdf"
	case strings.Contains(uvBin, "/pipx/venvs/") || strings.Contains(uvBin, "/pipx/shims/"):
		return "pipx"
	case strings.Contains(uvBin, "/Cellar/") || strings.HasPrefix(uvBin, "/opt/homebrew/") ||
		strings.HasPrefix(uvBin, "/usr/local/opt/") || strings.Contains(uvBin, "/.linuxbrew/"):
		return "brew"
	}

	// Check if it's a pip install (script lines 1546-1547)
	// pip puts uv in <env>/bin with the package in <env>/lib/python*/site-packages/uv
	parentDir := filepath.Dir(binDir)
	libPattern := filepath.Join(parentDir, "lib", "python*", "site-packages", "uv")
	matches, _ := filepath.Glob(libPattern)
	if len(matches) > 0 {
		return "pip"
	}

	// Check for standalone installer receipt (script lines 1548-1549)
	// Receipt is at $XDG_CONFIG_HOME/uv/uv-receipt.json (or $HOME/.config/uv/)
	xdgConfig := env.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(env.Home(), ".config")
	}
	receiptPath := filepath.Join(xdgConfig, "uv", "uv-receipt.json")

	if data, err := os.ReadFile(receiptPath); err == nil {
		// Check if the receipt mentions this binary's directory
		// The script does: grep -q -F "\"$d\"" where d is the bin directory
		dirToCheck := fmt.Sprintf("\"%s\"", binDir)
		if strings.Contains(string(data), dirToCheck) {
			return "standalone"
		}
		// Also check with the resolved directory
		resolvedDir := filepath.Dir(resolved)
		dirToCheck = fmt.Sprintf("\"%s\"", resolvedDir)
		if strings.Contains(string(data), dirToCheck) {
			return "standalone"
		}
	}

	// Check for cargo install (script line 1550)
	if strings.HasPrefix(uvBin, filepath.Join(env.Home(), ".cargo", "bin")) {
		return "cargo"
	}

	return "unknown"
}

// upgradeCmd returns the upgrade command for the given install method.
// This ports uv_upgrade_cmd from the bash script (lines 1555-1566).
func upgradeCmd(method string) string {
	switch method {
	case "standalone":
		return "uv self update"
	case "brew":
		return "brew upgrade uv"
	case "pipx":
		return "pipx upgrade uv"
	case "pip":
		return "pip install --upgrade uv   (in the environment that owns it)"
	case "cargo":
		return "cargo install --locked --force uv"
	case "mise":
		return "mise use -g uv@latest   (mise manages this uv)"
	case "asdf":
		return "asdf install uv latest && asdf global uv latest"
	default:
		return "uv self update   (standalone install), or your package manager: brew upgrade uv / pipx upgrade uv"
	}
}

// uvFix implements fixrun.Fix for a standalone uv binary.
type uvFix struct {
	path     string
	oldVer   string
	method   string
	fixedVer string
}

func (f *uvFix) Kind() string   { return kindID }
func (f *uvFix) Target() string { return f.path }

// Run executes the uv self update fix.
// This ports fix_uv from the bash script (lines 2650-2683).
func (f *uvFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	// Script line 2654: fx_say
	s.Say("%s  %s  (%s, install method: %s)", s.Bold("uv"), f.path, f.oldVer, f.method)

	// Script line 2655-2657: reject non-standalone installs
	if f.method != "standalone" {
		cmd := upgradeCmd(f.method)
		s.Warn("this uv was not installed by the standalone installer, so 'uv self update' is not used. Run: %s", cmd)
		s.Say("Note: this step upgrades uv only. Python versions and tools are handled separately by --only=uvpython and --only=uvtools.")
		return fixrun.Skipped
	}

	// Script line 2659-2662: dry run
	if s.DryRun {
		s.Cmd("%s self update", f.path)
		s.Say("[dry-run] would then re-read 'uv --version' and compare it with %s; nothing is changed now", f.fixedVer)
		return fixrun.Skipped
	}

	// Script line 2664: confirmation
	if !s.Confirm(fmt.Sprintf("Upgrade uv with '%s self update'?", f.path)) {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Script lines 2665-2666: backup the binary
	bak := filepath.Join(s.TempDir, "uv.bak")
	s.Cmd("cp -p %s %s", f.path, bak)
	result := s.Run.Run(ctx, "cp", "-p", f.path, bak)
	if result.Error != nil {
		s.Bad("could not back up %s - nothing was changed", f.path)
		s.Say("Note: this step upgrades uv only. Python versions and tools are handled separately by --only=uvpython and --only=uvtools.")
		return fixrun.Failed
	}

	// Script lines 2667-2668: run self update
	s.Cmd("%s self update", f.path)
	result = s.Run.Run(ctx, f.path, "self update")
	if result.Stdout != "" {
		// Print the output, limited to last 6 lines like the script
		lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
		start := 0
		if len(lines) > 6 {
			start = len(lines) - 6
		}
		for _, line := range lines[start:] {
			s.Say("      %s", line)
		}
	}

	// Script lines 2669-2682: verify the update
	newVerResult := s.Run.Run(ctx, f.path, "--version")
	newVer := discover.ExtractVersion(newVerResult.Stdout)

	var outcome fixrun.Outcome
	if newVer == "" {
		// Script lines 2670-2672: uv no longer reports a version - restore the backup
		s.Bad("uv no longer reports a version - restoring the previous binary")
		s.Run.Run(ctx, "cp", "-p", bak, f.path)
		outcome = fixrun.Failed
	} else {
		v := version.Parse(newVer)
		fixed := version.Parse(f.fixedVer)

		if v.GE(fixed) {
			// Script lines 2674-2678: success
			s.OK("uv --version now reports %s (fixed in %s). This is a version check, not a TLS probe.", newVer, f.fixedVer)
			s.Note("uv: %s -> %s", f.oldVer, newVer)
			outcome = fixrun.Changed
		} else {
			// Script lines 2679-2680: still behind - do NOT restore
			// "the binary still works" - no restore in this case
			s.Bad("uv reports %s, still behind %s (the update may not have happened) - the binary still works", newVer, f.fixedVer)
			outcome = fixrun.Failed
		}
	}

	// Script line 2681: print the note after the if/else in ALL cases
	s.Say("Note: this step upgrades uv only. Python versions and tools are handled separately by --only=uvpython and --only=uvtools.")

	return outcome
}
