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

// Package node implements the Kind for Node.js installations.
// It audits Node.js binaries, probes TLS trust, and offers upgrades via nvm
// for nvm-managed installations. Ports audit_node, check_node_version,
// node_candidates, node_upgrade_hint, fix_node, fix_node_nvm, offer_node_removal
// from the legacy bash script (lines 1342-2645).
package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

const (
	// kindID is the stable identifier for this Kind.
	kindID = "node"
)

// Fixed versions per major release line (from the advisory).
// Ports the script's check_node_version fixed versions.
var nodeLineFixedVersions = map[string]string{
	"22": "22.23.4",
	"24": "24.22.1",
	"26": "26.12.1",
}

// probeJSSrc is the embedded JavaScript probe source for Node.js.
// This is ported from the legacy script (lines 1290-1302).
const probeJSSrc = `for (const u of process.argv.slice(2)) {
  const isControl = u.includes("github.com");
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

// Kind implements kinds.Kind and kinds.Fixer for Node.js installations.
type Kind struct{}

// New creates a new node Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "node".
func (k *Kind) ID() string {
	return kindID
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Node.js installations"
}

// Applicable returns true for both macOS and Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	return kinds.Applicability{Applies: true}
}

// NodeLineCheck checks a Node.js version against the fixed versions for its major line.
// Ports check_node_version from the bash script (lines 1342-1357).
func NodeLineCheck(ver string) (check kinds.VersionCheck, fixed string, note string) {
	if ver == "" {
		return kinds.VersionUnknown, "", ""
	}
	// Strip leading 'v'
	v := strings.TrimPrefix(ver, "v")

	// Extract major version
	dotIdx := strings.Index(v, ".")
	major := v
	if dotIdx > 0 {
		major = v[:dotIdx]
	}

	// Check for fixed version for this major line
	fixv, hasFix := nodeLineFixedVersions[major]
	if !hasFix {
		// No fix published for this major line
		// Parse major as integer for comparison
		majorParts := version.Parse(major).Parts
		majorInt := 0
		if len(majorParts) > 0 {
			majorInt = majorParts[0]
		}
		if majorInt > 26 {
			// Newer than the fixed lines
			return kinds.VersionOK, "", "newer than the fixed lines"
		}
		// Older than 22, or between fixed lines (e.g., 23, 25)
		return kinds.VersionNoFix, "22.23.4, 24.22.1 or 26.12.1", "fixes only published for 22.23.4, 24.22.1, 26.12.1"
	}

	// Compare with fixed version for this line
	pv := version.Parse(v)
	fixpv := version.Parse(fixv)
	if pv.GE(fixpv) {
		return kinds.VersionOK, fixv, "fixed in " + fixv
	}
	return kinds.VersionBehind, fixv, "fixed in " + fixv
}

// Audit discovers Node.js installations and returns findings.
// Ports audit_node from the bash script (lines 1420-1458).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	seen := &discover.Seen{}
	candidates := k.candidates(env)

	// Write probe.js to temp directory
	probeFile := filepath.Join(env.TempDir, "node_probe.js")
	if err := os.WriteFile(probeFile, []byte(probeJSSrc), 0644); err != nil {
		env.Log.Error("failed to write node_probe.js", "error", err)
		return nil, fmt.Errorf("failed to write node probe: %w", err)
	}

	for _, n := range candidates {
		// Resolve symlinks and dedupe
		resolved := discover.Resolve(n)
		key := kindID + ":" + resolved
		if !seen.First(key) {
			continue
		}

		// Get version
		ver := k.getNodeVersion(ctx, env, n)

		// Create finding
		f := kinds.NewFinding(k.ID(), "Node.js")
		f.Path = n

		// Check version against fixed versions per line
		vc, fixv, note := NodeLineCheck(ver)
		if ver != "" && ver != "?" {
			f.SetVersion(ver, fixv, vc, note)
		}

		// Run TLS probe
		var probeResult kinds.ProbeResult
		var probeEvidence string
		if env.Offline {
			probeResult = kinds.ProbeSkipped
			probeEvidence = "--no-network"
		} else {
			probeResult = k.probeNode(ctx, env, n, probeFile)
			probeEvidence = describeProbeResult(probeResult)
		}
		f.SetProbe(probeResult, probeEvidence)

		// Secondary probe with --use-system-ca when affected
		var sysCaResult kinds.ProbeResult
		var sysCaEvidence string
		if probeResult == kinds.ProbeTrusted {
			if k.hasUseSystemCA(ctx, env, n) {
				sysCaResult = k.probeNodeWithFlag(ctx, env, n, probeFile, "--use-system-ca")
				sysCaEvidence = describeProbeResult(sysCaResult)
			} else {
				sysCaResult = kinds.ProbeSkipped
				sysCaEvidence = "no --use-system-ca"
			}
		}

		// Add guidance when affected or behind
		if probeResult == kinds.ProbeTrusted || vc == kinds.VersionBehind || vc == kinds.VersionNoFix {
			how := k.whereFrom(ctx, env, n)
			k.addGuidance(&f, n, ver, fixv, how, sysCaResult, sysCaEvidence)

			// Mark as having a fix if it's an nvm installation and version is behind
			// (the script's plan_node_major logic)
			if how == "nvm" && vc == kinds.VersionBehind {
				f.HasFix = true
			}
		}

		// Add secondary probe info to evidence
		if sysCaResult != "" {
			f.Evidence = fmt.Sprintf("%s\n    with --use-system-ca: %s", f.Evidence, sysCaEvidence)
		}

		// Add environment variable notes
		envNotes := k.envNotes(env)
		if envNotes != "" && f.Evidence != "" {
			f.Evidence = f.Evidence + "\n    " + envNotes
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// candidates returns candidate Node.js installations.
// Ports node_candidates from the bash script (lines 1359-1376).
func (k *Kind) candidates(env *kinds.Env) []string {
	var patterns []string

	// Testing aid: EMUDHRA_NODE_BINS names a directory of version folders
	if nodeBins := env.Getenv("EMUDHRA_NODE_BINS"); nodeBins != "" {
		// List all node binaries under the version folders
		entries, err := os.ReadDir(nodeBins)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(nodeBins, entry.Name(), "bin", "node")
					if discover.Executables([]string{nodeBin}) != nil {
						patterns = append(patterns, nodeBin)
					}
				}
			}
		}
		// Return only these when the testing aid is set
		if len(patterns) > 0 {
			return patterns
		}
	}

	// PATH lookup
	if node := discover.Lookup("node", env.Path()); node != "" {
		patterns = append(patterns, node)
	}

	home := env.Home()
	nvmDir := env.Getenv("NVM_DIR")
	if nvmDir == "" && home != "" {
		nvmDir = filepath.Join(home, ".nvm")
	}

	// nvm installations
	if nvmDir != "" {
		versionsDir := filepath.Join(nvmDir, "versions", "node")
		if entries, err := os.ReadDir(versionsDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "v") {
					nodeBin := filepath.Join(versionsDir, entry.Name(), "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}
	}

	// volta installations
	if home != "" {
		voltaDir := filepath.Join(home, ".volta", "tools", "image", "node")
		if entries, err := os.ReadDir(voltaDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(voltaDir, entry.Name(), "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}

		// fnm installations (Linux)
		fnmDir := filepath.Join(home, ".local", "share", "fnm", "node-versions")
		if entries, err := os.ReadDir(fnmDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(fnmDir, entry.Name(), "installation", "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}

		// fnm installations (macOS)
		fnmMacDir := filepath.Join(home, "Library", "Application Support", "fnm", "node-versions")
		if entries, err := os.ReadDir(fnmMacDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(fnmMacDir, entry.Name(), "installation", "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}

		// asdf installations
		asdfDir := filepath.Join(home, ".asdf", "installs", "nodejs")
		if entries, err := os.ReadDir(asdfDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(asdfDir, entry.Name(), "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}

		// mise installations
		miseDir := filepath.Join(home, ".local", "share", "mise", "installs", "node")
		if entries, err := os.ReadDir(miseDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					nodeBin := filepath.Join(miseDir, entry.Name(), "bin", "node")
					patterns = append(patterns, nodeBin)
				}
			}
		}
	}

	// Homebrew installations
	patterns = append(patterns,
		"/opt/homebrew/opt/node@22/bin/node",
		"/opt/homebrew/opt/node@24/bin/node",
		"/opt/homebrew/opt/node@26/bin/node",
		"/opt/homebrew/opt/node/bin/node",
		"/usr/local/opt/node@22/bin/node",
		"/usr/local/opt/node@24/bin/node",
		"/usr/local/opt/node@26/bin/node",
		"/usr/local/opt/node/bin/node",
	)

	// System installations
	patterns = append(patterns,
		"/usr/local/bin/node",
		"/usr/bin/node",
	)

	return discover.Executables(discover.Candidates(patterns...))
}

// getNodeVersion runs `node --version` and extracts the version.
func (k *Kind) getNodeVersion(ctx context.Context, env *kinds.Env, nodePath string) string {
	result := env.Run.RunWithInput(ctx, "", nodePath, "--version")
	if result.Error != nil || result.ExitCode != 0 {
		return "?"
	}
	// Shown as node prints it ("v24.22.1"); the line checks strip the "v" themselves.
	return strings.TrimSpace(result.Stdout)
}

// probeNode runs a TLS probe using the Node.js installation.
// Ports runtime_probe from the bash script.
func (k *Kind) probeNode(ctx context.Context, env *kinds.Env, nodePath, probeFile string) kinds.ProbeResult {
	// Build URLs: control URL first, then bad URLs
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)

	// Run: node probe.js <urls>
	args := append([]string{probeFile}, urls...)
	result := env.Run.RunWithInput(ctx, "", nodePath, args...)

	if result.Error != nil {
		env.Log.Debug("probe failed", "error", result.Error, "stderr", result.Stderr)
		return kinds.ProbeInconclusive
	}

	// Judge the output
	return kinds.ResultOf(probe.JudgeOutput(result.Stdout))
}

// probeNodeWithFlag runs the probe with additional flags.
func (k *Kind) probeNodeWithFlag(ctx context.Context, env *kinds.Env, nodePath, probeFile string, flag string) kinds.ProbeResult {
	urls := append([]string{probe.CONTROL_URL}, probe.BAD_URLS...)
	args := append([]string{flag, probeFile}, urls...)
	result := env.Run.RunWithInput(ctx, "", nodePath, args...)

	if result.Error != nil {
		return kinds.ProbeInconclusive
	}

	return kinds.ResultOf(probe.JudgeOutput(result.Stdout))
}

// hasUseSystemCA checks if the Node.js binary supports --use-system-ca.
func (k *Kind) hasUseSystemCA(ctx context.Context, env *kinds.Env, nodePath string) bool {
	// node -e 0 exits cleanly; try with --use-system-ca
	result := env.Run.RunWithInput(ctx, "", nodePath, "--use-system-ca", "-e", "0")
	return result.ExitCode == 0
}

// describeProbeResult returns a human-readable description of the probe verdict.
func describeProbeResult(r kinds.ProbeResult) string {
	switch r {
	case kinds.ProbeTrusted:
		return "trusted:connected to compromised chain"
	case kinds.ProbeRejected:
		return "rejected:certificate rejected"
	case kinds.ProbeInconclusive:
		return "inconclusive:control host failed"
	case kinds.ProbeSkipped:
		return "skipped"
	default:
		return string(r)
	}
}

// whereFrom determines how Node.js was installed (nvm, volta, fnm, asdf, mise, brew, or system).
// Ports where_from from the bash script.
func (k *Kind) whereFrom(ctx context.Context, env *kinds.Env, nodePath string) string {
	home := env.Home()

	// Check nvm
	nvmDir := env.Getenv("NVM_DIR")
	if nvmDir == "" && home != "" {
		nvmDir = filepath.Join(home, ".nvm")
	}
	if nvmDir != "" && strings.Contains(nodePath, nvmDir) {
		return "nvm"
	}

	// Check volta
	if home != "" && strings.Contains(nodePath, filepath.Join(home, ".volta")) {
		return "volta"
	}

	// Check fnm
	if home != "" && (strings.Contains(nodePath, filepath.Join(home, ".local", "share", "fnm")) ||
		strings.Contains(nodePath, filepath.Join(home, "Library", "Application Support", "fnm"))) {
		return "fnm"
	}

	// Check asdf
	if home != "" && strings.Contains(nodePath, filepath.Join(home, ".asdf", "installs", "nodejs")) {
		return "asdf"
	}

	// Check mise
	if home != "" && strings.Contains(nodePath, filepath.Join(home, ".local", "share", "mise", "installs", "node")) {
		return "mise"
	}

	// Check Homebrew
	if strings.Contains(nodePath, "/opt/homebrew/") || strings.Contains(nodePath, "/usr/local/opt/") {
		return "brew"
	}

	return "system"
}

// upgradeHint returns the install command for the version manager in use.
// Ports node_upgrade_hint from the bash script (lines 1379-1389).
func upgradeHint(how, fixv string) string {
	switch how {
	case "nvm":
		return fmt.Sprintf("nvm install %s", fixv)
	case "volta":
		return fmt.Sprintf("volta install node@%s", fixv)
	case "fnm":
		return fmt.Sprintf("fnm install %s", fixv)
	case "mise":
		return fmt.Sprintf("mise use -g node@%s", fixv)
	case "asdf":
		return fmt.Sprintf("asdf install nodejs %s", fixv)
	case "brew":
		return "brew upgrade node"
	default:
		return "https://nodejs.org"
	}
}

// addGuidance adds remediation guidance to the finding.
// Ports fix_node from the bash script (lines 1391-1418).
func (k *Kind) addGuidance(f *kinds.Finding, nodePath, ver, fixv, how string, sysCaResult kinds.ProbeResult, sysCaEvidence string) {
	// Primary upgrade guidance
	hint := upgradeHint(how, fixv)
	compact := fmt.Sprintf("upgrade Node.js to %s or later (%s)", fixv, hint)

	var full []string

	// Version-manager-specific commands
	switch how {
	case "nvm":
		full = append(full,
			fmt.Sprintf("nvm install %s && nvm alias default %s   # then: nvm uninstall %s", fixv, fixv, ver),
		)
	case "volta":
		full = append(full, fmt.Sprintf("volta install node@%s", fixv))
	case "fnm":
		full = append(full, fmt.Sprintf("fnm install %s && fnm default %s", fixv, fixv))
	case "mise":
		full = append(full, fmt.Sprintf("mise use -g node@%s", fixv))
	case "asdf":
		full = append(full, fmt.Sprintf("asdf install nodejs %s && asdf global nodejs %s", fixv, fixv))
	case "brew":
		full = append(full, "brew update && brew upgrade node")
	default:
		full = append(full, fmt.Sprintf("Install Node.js %s or later (https://nodejs.org/en/download or your package manager).", fixv))
	}

	// Node.js uses its own bundled CA list by default
	full = append(full,
		"Node.js uses its own bundled CA list by default, so editing OS bundles does not normally change it",
		"(unless NODE_EXTRA_CA_CERTS or --use-system-ca is in play): upgrade the runtime.",
	)

	// Secondary guidance based on --use-system-ca probe
	switch sysCaEvidence {
	case "rejected":
		full = append(full,
			"Stop-gap: run with --use-system-ca (or NODE_USE_SYSTEM_CA=1) so Node uses the OS trust store.",
			"Tested here: with that flag Node rejects the chain, because this OS store already blocks it. That only",
			"holds while the OS store stays patched, so still upgrade the runtime.",
		)
	case "trusted":
		full = append(full,
			"Tested here: --use-system-ca does not help; Node still accepts the chain with it (it may not apply the",
			"OS revocation block). Upgrading the runtime is the fix.",
		)
	case "no --use-system-ca":
		full = append(full,
			"This Node has no --use-system-ca, so upgrading is the only fix.",
		)
	}

	full = append(full, "(Fixed releases: 22.23.4, 24.22.1, 26.12.1.)")

	f.AddGuidance(compact, full...)
}

// envNotes returns environment variable notes for Node.js.
// Ports env_notes NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA from the bash script.
func (k *Kind) envNotes(env *kinds.Env) string {
	var notes []string
	if v := env.Getenv("NODE_EXTRA_CA_CERTS"); v != "" {
		notes = append(notes, fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", v))
	}
	if v := env.Getenv("NODE_USE_SYSTEM_CA"); v != "" {
		notes = append(notes, fmt.Sprintf("NODE_USE_SYSTEM_CA=%s", v))
	}
	return strings.Join(notes, " ")
}
