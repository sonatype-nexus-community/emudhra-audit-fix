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

package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// FixOrder returns the fix order for Node.js fixes.
func (k *Kind) FixOrder() int {
	return kinds.FixNode
}

// Plan turns findings into fixes for nvm-managed Node.js installations.
// This ports plan_node_major from the bash script (lines 2441-2460):
// one fix per major line, targeting the newest installed binary of that line.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	// Group findings by major line, keeping only nvm installations that are behind
	// This mirrors the script's plan_node_major: only findings with HasFix=true
	// (nvm + behind) reach here.
	type majorLine struct {
		major   string
		best    string // newest version of this major line
		bestVer string
		fixed   string // fixed version for this major line
	}

	byMajor := make(map[string]*majorLine)

	for _, f := range findings {
		// Plan receives every Kind's findings; act only on this Kind's own.
		if f.Kind != k.ID() {
			continue
		}
		if !f.HasFix {
			continue
		}
		how := k.whereFrom(ctx, env, f.Path)
		if how != "nvm" {
			continue
		}

		// Extract major from version
		v := strings.TrimPrefix(f.Version, "v")
		dotIdx := strings.Index(v, ".")
		major := v
		if dotIdx > 0 {
			major = v[:dotIdx]
		}

		// Get fixed version for this major
		fixed, ok := nodeLineFixedVersions[major]
		if !ok {
			// No fix for this major - should not happen given HasFix logic
			continue
		}

		// Only consider versions that are behind (not already fixed)
		if f.VersionCheck != kinds.VersionBehind {
			continue
		}

		// Keep the newest version of this major line
		// (closest to the fixed release, so --reinstall-packages-from copies
		// the most relevant packages)
		entry, exists := byMajor[major]
		if !exists {
			byMajor[major] = &majorLine{
				major:   major,
				best:    f.Path,
				bestVer: v,
				fixed:   fixed,
			}
		} else {
			// Compare versions, keep newer
			pv := version.Parse(v)
			bestPV := version.Parse(entry.bestVer)
			if pv.Compare(bestPV) > 0 {
				entry.best = f.Path
				entry.bestVer = v
			}
		}
	}

	// Create one fix per major line
	var fixes []fixrun.Fix
	for _, entry := range byMajor {
		fixes = append(fixes, &nvmFix{
			nodePath:     entry.best,
			oldVersion:   entry.bestVer,
			fixedVersion: entry.fixed,
			nvmDir:       k.nvmDir(env),
		})
	}

	// Sort by major version for consistent ordering
	sort.Slice(fixes, func(i, j int) bool {
		return fixes[i].(*nvmFix).fixedVersion < fixes[j].(*nvmFix).fixedVersion
	})

	return fixes, nil
}

// nvmDir returns the NVM_DIR environment variable or the default ~/.nvm.
func (k *Kind) nvmDir(env *kinds.Env) string {
	if d := env.Getenv("NVM_DIR"); d != "" {
		return d
	}
	if home := env.Home(); home != "" {
		return filepath.Join(home, ".nvm")
	}
	return ""
}

// nvmFix implements fixrun.Fix for upgrading Node.js via nvm.
// This ports fix_node_nvm, nvm_run, nvm_run_seq, nvm_aliases_for,
// nvm_removable_versions, and offer_node_removal from the bash script
// (lines 2432-2637).
type nvmFix struct {
	nodePath     string // path to the old node binary
	oldVersion   string // version of the old node (e.g., "24.16.0")
	fixedVersion string // fixed version to install (e.g., "24.22.1")
	nvmDir       string // NVM_DIR path
}

// Kind returns "node".
func (f *nvmFix) Kind() string { return kindID }

// Target returns the path being fixed.
func (f *nvmFix) Target() string { return f.nodePath }

// Run executes the nvm upgrade flow.
// This ports fix_node_nvm from the bash script (lines 2487-2563).
func (f *nvmFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	// Say what we're doing
	s.Say("")
	s.Say("%sNode.js (nvm)%s  %s", s.Bold(""), s.Bold(""), f.nodePath)

	oldv := f.oldVersion
	fixed := f.fixedVersion
	if fixed == "" {
		s.Warn("no fixed Node.js release is published for %s's major line (fixed: 22.23.4, 24.22.1, 26.12.1) - not guessing a different major", "v"+oldv)
		return fixrun.Skipped
	}

	// Check nvm.sh exists
	nvmSh := filepath.Join(f.nvmDir, "nvm.sh")
	if _, err := os.Stat(nvmSh); os.IsNotExist(err) {
		s.Warn("%s/nvm.sh not found - cannot drive nvm (set NVM_DIR if nvm lives elsewhere)", f.nvmDir)
		return fixrun.Skipped
	}

	newBinPath := filepath.Join(f.nvmDir, "versions", "node", "v"+fixed, "bin", "node")

	s.Say("installed: v%s   fixed in: v%s (same major line; this is an upgrade, not a trust-store edit)", oldv, fixed)

	// Check if fixed version is already installed
	newInstalled := false
	if _, err := os.Stat(newBinPath); err == nil {
		s.Say("v%s is already installed", fixed)
		newInstalled = true
	}

	// In dry-run mode, print what would happen and stop
	if s.DryRun {
		if !newInstalled {
			s.Cmd("nvm install v%s --reinstall-packages-from=v%s", fixed, oldv)
		}
		s.Cmd("# then, only if v%s is your current default: nvm alias default v%s   (asked separately)", oldv, fixed)
		s.Say("[dry-run] afterwards, each older v%s.x that is not your default or aliased would be offered for removal", strings.Split(fixed, ".")[0])
		s.Say("[dry-run] behind a type-I-AGREE prompt that --yes cannot answer (nvm uninstall v%s); nothing is removed now", oldv)
		return fixrun.Skipped
	}

	// If not already installed, check availability and install
	if !newInstalled {
		// Check if the fixed release is available via nvm
		availResult := s.Run.Run(ctx, "bash", "-c",
			fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm version-remote %s | tail -1`,
				f.nvmDir, strings.Split(fixed, ".")[0]))
		if availResult.ExitCode == 0 {
			avail := strings.TrimSpace(availResult.Stdout)
			avail = strings.TrimPrefix(avail, "v")
			if avail == "" || avail == "N/A" {
				s.Warn("nvm does not offer %s.x yet; the fixed release %s is not available yet - not changing anything", strings.Split(fixed, ".")[0], fixed)
				return fixrun.Skipped
			}
			availVer := version.Parse(avail)
			fixedVer := version.Parse(fixed)
			if !availVer.GE(fixedVer) {
				s.Warn("nvm reports %s as the newest %s.x; the fixed release %s is not available yet - not changing anything", avail, strings.Split(fixed, ".")[0], fixed)
				return fixrun.Skipped
			}
		}

		// Confirm installation
		if !s.Confirm(fmt.Sprintf("Install Node.js v%s with nvm (global npm packages are copied from v%s)?", fixed, oldv)) {
			s.Say("skipped")
			return fixrun.Skipped
		}

		// Install
		s.Cmd("nvm install v%s --reinstall-packages-from=v%s", fixed, oldv)
		installOut := s.Run.Run(ctx, "bash", "-c",
			fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm install v%s --reinstall-packages-from=v%s 2>&1`,
				f.nvmDir, fixed, oldv))

		// Check if install succeeded
		if _, err := os.Stat(newBinPath); os.IsNotExist(err) {
			s.Bad("nvm did not install v%s (offline, mirror down or interrupted) - nothing was changed", fixed)
			return fixrun.Failed
		}

		// Print some of the output
		lines := strings.Split(installOut.Stdout, "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		for _, l := range lines {
			if l != "" {
				s.Say("      %s", l)
			}
		}
	} else {
		// Already installed - ask to use it
		if !s.Confirm(fmt.Sprintf("Use the already-installed v%s?", fixed)) {
			s.Say("skipped")
			return fixrun.Skipped
		}
	}

	// Verify the new binary rejects the compromised chain
	probeFile := filepath.Join(s.TempDir, "node_probe.js")
	if err := os.WriteFile(probeFile, []byte(probeJSSrc), 0644); err != nil {
		s.Bad("failed to write probe file: %v", err)
		return fixrun.Failed
	}

	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)
	args := append([]string{probeFile}, urls...)
	result := s.Run.Run(ctx, newBinPath, args...)
	nvmResult := kinds.ResultOf(probe.JudgeOutput(result.Stdout))

	switch nvmResult {
	case kinds.ProbeRejected:
		s.OK("verified: %s rejects the compromised chain", newBinPath)
	default:
		s.Bad("v%s is installed but does not reject the chain (%s) - leaving your default alone", fixed, describeProbeResult(nvmResult))
		return fixrun.Failed
	}

	// Handle the default alias
	curDefault := f.nvmVersionDefault(ctx, s.Run)
	if "v"+oldv == curDefault {
		if s.Confirm(fmt.Sprintf("v%s is your nvm default. Make v%s the default (nvm alias default v%s)?", oldv, fixed, fixed)) {
			s.Cmd("nvm alias default v%s", fixed)
			aliasOut := s.Run.Run(ctx, "bash", "-c",
				fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm alias default v%s`,
					f.nvmDir, fixed))
			if aliasOut.ExitCode == 0 {
				s.OK("default is now v%s", fixed)
				s.Note("nvm default alias: v%s -> v%s (undo: nvm alias default v%s)", oldv, fixed, oldv)
			} else {
				s.Warn("could not set the default alias")
			}
		} else {
			s.Say("default left as v%s; new shells will keep using it until you change it", oldv)
		}
	} else {
		s.Say("your nvm default is %s, not v%s - not changing it", curDefault, oldv)
	}

	s.Note("Node.js: installed v%s beside v%s", fixed, oldv)

	// Offer to remove older versions of the same major line
	f.offerNodeRemoval(ctx, s, fixed)

	return fixrun.Changed
}

// nvmVersionDefault returns the current nvm default version.
func (f *nvmFix) nvmVersionDefault(ctx context.Context, runner exec.Runner) string {
	result := runner.Run(ctx, "bash", "-c",
		fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm version default | tail -1`, f.nvmDir))
	return strings.TrimSpace(result.Stdout)
}

// nvmAliases returns all aliases via `nvm alias`.
func (f *nvmFix) nvmAliases(ctx context.Context, runner exec.Runner) map[string][]string {
	// Returns map[version][]aliasName
	result := runner.Run(ctx, "bash", "-c",
		fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm alias 2>/dev/null`, f.nvmDir))

	aliases := make(map[string][]string)
	// Parse output: "name -> some_path (-> vX.Y.Z)"
	for _, line := range strings.Split(result.Stdout, "\n") {
		// Strip ANSI codes
		line = strings.ReplaceAll(line, "\x1b[0m", "")
		line = strings.Map(func(r rune) rune {
			if r >= 32 || r == '\t' {
				return r
			}
			return -1
		}, line)

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		name := parts[0]

		// Find the version in the line: look for "(-> vX.Y.Z)" pattern
		if idx := strings.Index(line, "(-> v"); idx >= 0 {
			rest := line[idx+4:]
			if endIdx := strings.Index(rest, ")"); endIdx > 0 {
				ver := rest[:endIdx]
				aliases[ver] = append(aliases[ver], name)
			}
		}
	}
	return aliases
}

// nvmRemovableVersions returns old versions of the same major that are safe to offer for removal.
// Ports nvm_removable_versions from the bash script (lines 2574-2589).
func (f *nvmFix) nvmRemovableVersions(ctx context.Context, s *fixrun.Session) []removableVersion {
	major := strings.Split(f.fixedVersion, ".")[0]
	versionsDir := filepath.Join(f.nvmDir, "versions", "node")

	var removables []removableVersion

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return nil
	}

	// Get default version
	curDefault := f.nvmVersionDefault(ctx, s.Run)

	// Get aliases
	aliases := f.nvmAliases(ctx, s.Run)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "v"+major+".") {
			continue
		}

		v := strings.TrimPrefix(name, "v")
		fixedVer := version.Parse(f.fixedVersion)
		vVer := version.Parse(v)

		// Skip the fixed version or newer
		if vVer.GE(fixedVer) {
			continue
		}

		// Check if it's the default
		var reasons []string
		if "v"+v == curDefault {
			reasons = append(reasons, "it is your nvm default")
		}

		// Check for aliases
		if als, ok := aliases["v"+v]; ok && len(als) > 0 {
			reasons = append(reasons, fmt.Sprintf("aliases point at it: %s", strings.Join(als, " ")))
		}

		removables = append(removables, removableVersion{
			version: v,
			reasons: reasons,
		})
	}

	return removables
}

type removableVersion struct {
	version string
	reasons []string
}

// offerNodeRemoval offers to remove older versions of the same major line.
// Ports offer_node_removal from the bash script (lines 2593-2637).
func (f *nvmFix) offerNodeRemoval(ctx context.Context, s *fixrun.Session, fixed string) {
	removables := f.nvmRemovableVersions(ctx, s)

	if len(removables) == 0 {
		s.Say("no older v%s.x versions are installed, so there is nothing to remove", strings.Split(fixed, ".")[0])
		return
	}

	for _, rv := range removables {
		if len(rv.reasons) > 0 {
			s.Say("keeping v%s: %s", rv.version, strings.Join(rv.reasons, "; "))
			continue
		}

		warning := fmt.Sprintf(`
  WARNING: this permanently deletes Node.js v%s from nvm.

  Before you continue, be aware that:
    - it is the version with the compromised-chain problem, so removing it is the safest end state, BUT
    - any project that pins it (an .nvmrc, .node-version, engines field, a CI script or a shell alias) will
      stop working until it is pointed at v%s or newer;
    - global npm packages installed only under v%s are deleted with it (the upgrade copied them to v%s);
    - running processes and shells currently using v%s keep running, but new shells will not find it;
    - this cannot be undone except by reinstalling it: nvm install v%s   (a reinstall brings the problem back).

  Command that will run: nvm uninstall v%s`, rv.version, fixed, rv.version, fixed, rv.version, rv.version, rv.version)

		if !s.ConfirmAgree(warning) {
			s.Say("kept v%s (nothing typed, or not exactly I AGREE)", rv.version)
			continue
		}

		s.Cmd("nvm deactivate && nvm uninstall v%s", rv.version)

		// Run deactivate then uninstall in a single subshell
		// This ports nvm_run_seq from the bash script (lines 2465-2474)
		result := s.Run.Run(ctx, "bash", "-c",
			fmt.Sprintf(`export NVM_DIR="%s"; . "$NVM_DIR/nvm.sh" >/dev/null 2>&1; nvm deactivate >/dev/null 2>&1; nvm uninstall v%s 2>&1`,
				f.nvmDir, rv.version))

		versionDir := filepath.Join(f.nvmDir, "versions", "node", "v"+rv.version)
		if _, err := os.Stat(versionDir); os.IsNotExist(err) {
			s.OK("removed v%s", rv.version)
			s.Note("Node.js: removed v%s (reinstall with: nvm install v%s)", rv.version, rv.version)
		} else {
			s.Bad("nvm could not remove v%s; it is still installed. nvm said:", rv.version)
			lines := strings.Split(result.Stdout, "\n")
			if len(lines) > 6 {
				lines = lines[:6]
			}
			for _, l := range lines {
				if l != "" {
					s.Say("        %s", l)
				}
			}
			s.Say("To finish it yourself, open a NEW shell (one that does not have v%s active) and run: nvm uninstall v%s", rv.version, rv.version)
		}
	}
}
