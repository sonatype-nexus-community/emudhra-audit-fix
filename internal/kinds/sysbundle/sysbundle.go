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

// Package sysbundle audits and patches system CA bundle files.
// It tests /etc/ssl/cert.pem and other common Linux/BSD locations directly
// via the probe engine. Handles macOS, Linux, FreeBSD, and NetBSD.
// Ports fix_pem_bundle from the bash script (lines 2127-2182).
package sysbundle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/trust"
)

// SectionTitle is the audit_start title for System CA bundle files, shown in verbose mode.
const SectionTitle = "System CA bundle files"

// brewPrefix is a function that returns the Homebrew prefix for the environment.
// The default implementation checks HOMEBREW_PREFIX and falls back to /opt/homebrew
// if it exists. The orchestrator should replace this with brew.Prefix after merge.
var brewPrefix = func(env *kinds.Env) string {
	if bp := env.Getenv("HOMEBREW_PREFIX"); bp != "" {
		return bp
	}
	// Default Apple Silicon location
	if _, err := os.Stat("/opt/homebrew"); err == nil {
		return "/opt/homebrew"
	}
	return ""
}

// Kind implements kinds.Kind for system CA bundle files.
type Kind struct{}

// New creates a new sysbundle Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier for this Kind.
func (k *Kind) ID() string {
	return "sysbundle"
}

// Describe returns a one-line human description.
func (k *Kind) Describe() string {
	return "System CA bundle files (/etc/ssl/cert.pem, etc.)"
}

// Applicable reports whether this Kind makes sense on this host.
// System CA bundles apply to Darwin, Linux, FreeBSD, and NetBSD.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	switch h.OS {
	case "darwin", "linux", "freebsd", "netbsd":
		return kinds.Applicability{
			Applies: true,
			Reason:  "",
		}
	default:
		return kinds.Applicability{
			Applies: false,
			Reason:  "macOS, Linux, FreeBSD, and NetBSD only",
		}
	}
}

// Audit discovers system CA bundle files and returns findings.
// This ports audit_sysbundle() from the bash script (lines 1623-1647).
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	// Get the dedupe key tracker
	seen := &discover.Seen{}

	// Get candidate bundle paths
	candidates := k.bundlePaths()

	// Check for brew prefix cert.pem (to dedupe with the brew Kind)
	// The script uses BREW_PREFIX to avoid double-reporting
	var brewBundle string
	if env.Host.OS == "darwin" {
		if bp := brewPrefix(env); bp != "" {
			brewCert := bp + "/etc/ca-certificates/cert.pem"
			if _, err := os.Stat(brewCert); err == nil {
				brewBundle = discover.Resolve(brewCert)
			}
		}
	}

	// Test each candidate bundle
	for _, path := range candidates {
		// Check if file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		// Resolve symlinks for deduplication
		resolved := discover.Resolve(path)
		key := "bundle:" + resolved

		// Skip if this is the same as the brew bundle (avoid duplicate)
		if brewBundle != "" && resolved == brewBundle {
			env.Log.Debug("skipping bundle - same as brew bundle", "path", path)
			continue
		}

		// Dedupe
		if !seen.First(key) {
			env.Log.Debug("skipping duplicate bundle", "path", path)
			continue
		}

		// Create finding
		finding := kinds.NewFinding(k.ID(), "CA bundle")
		finding.Path = path

		// Probe the bundle using SetProbe/SetVersion only
		if env.Offline {
			finding.SetProbe(kinds.ProbeSkipped, "--no-network")
		} else {
			// Probe the CA file using the probe engine
			results, err := probe.ProbeCAFile(ctx, path)
			if err != nil {
				finding.SetProbe(kinds.ProbeInconclusive, fmt.Sprintf("probe error: %v", err))
			} else {
				// Judge the results
				verdict := env.Probe.Judge(results)

				switch verdict {
				case probe.VerdictTrusted:
					finding.SetProbe(kinds.ProbeTrusted, "connected to a host using the compromised chain")
				case probe.VerdictRejected:
					finding.SetProbe(kinds.ProbeRejected, "certificate rejected")
				case probe.VerdictInconclusive:
					finding.SetProbe(kinds.ProbeInconclusive, "inconclusive - control host unreachable or network issue")
				case probe.VerdictSkipped:
					finding.SetProbe(kinds.ProbeSkipped, "skipped")
				}
			}
		}

		// Add version note (no actual version for bundles)
		finding.SetVersion("file", "", kinds.VersionNA, "no version; tested directly")

		// Add guidance for affected bundles
		if finding.Status() == kinds.StatusAffected {
			k.addGuidance(&finding)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// bundlePaths returns candidate CA bundle paths for the current platform.
// This ports the list from audit_sysbundle() (lines 1627-1629).
func (k *Kind) bundlePaths() []string {
	return []string{
		"/etc/ssl/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/ca-bundle.pem",
		"/usr/local/share/certs/ca-root-nss.crt",
	}
}

// addGuidance adds remediation guidance to a finding.
// This ports the tool-specific guidance from audit_sysbundle() in the bash script.
// The shared system trust store recipe is handled by Setting NeedsSystemGuidance flag.
func (k *Kind) addGuidance(finding *kinds.Finding) {
	// From bash script line 1643:
	//   fixc "patch this bundle (system trust store recipe with -v)"
	//   fix "This bundle still contains the roots the compromised chain leads to: see System trust store below."; FIXSYS=1
	//
	// We set NeedsSystemGuidance=true to request the shared OS recipe (the script's FIXSYS=1),
	// and keep only the tool-specific guidance here.
	finding.NeedsSystemGuidance = true
	finding.HasFix = true // The script calls plan_add sys for system bundle fixes

	// Compact guidance (one-line summary shown in compact mode)
	// Keep the script's 2-space indent
	finding.AddGuidance(
		"  patch this bundle (system trust store recipe with -v)",
		"  This bundle still contains the roots the compromised chain leads to: see System trust store below.",
	)
}

// Plan returns fixes for affected bundles.
// Ports fix_pem_bundle from the bash script (lines 2127-2182).
// FixOrder implements kinds.Fixer: where the system store fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixSys }

func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	// fix_system on macOS is fix_pem_bundle /etc/ssl/cert.pem, planned once per host
	// when any bad finding asks for the system trust store fix (plan_add sys system).
	// The Linux methods belong to ospkg.
	if env.Host.OS != "darwin" || !kinds.WantsSystemFix(findings) {
		return nil, nil
	}
	return []fixrun.Fix{&BundleFix{
		Path:        "/etc/ssl/cert.pem",
		Probe:       env.Probe,
		ProbeCAFile: probe.ProbeCAFile,
	}}, nil
}

// BundleFix patches a PEM bundle by removing the two distrusted roots.
// Ports fix_pem_bundle from the bash script (lines 2127-2182).
type BundleFix struct {
	Path        string
	Probe       probe.Engine
	ProbeCAFile func(ctx context.Context, caFile string) ([]probe.ProbeResult, error)
}

// Kind returns the owning Kind ID.
func (f *BundleFix) Kind() string { return "sysbundle" }

// Target names what is fixed, for messages.
func (f *BundleFix) Target() string { return f.Path }

// Run does the whole fix against the Session and reports the outcome.
// Ports fix_pem_bundle from the bash script (lines 2127-2182).
func (f *BundleFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	// Read the bundle
	data, err := os.ReadFile(f.Path)
	if err != nil {
		s.Warn("cannot read %s: %v", f.Path, err)
		return fixrun.Skipped
	}

	// Parse the bundle
	bundle, err := trust.ParseBundle(data)
	if err != nil {
		s.Warn("cannot parse bundle %s: %v", f.Path, err)
		return fixrun.Skipped
	}

	before := bundle.Count()
	s.Say("%s  (system CA bundle: read by the built-in curl, git, python3, perl, openssl)", s.Bold(f.Path))

	// Strip the roots
	strippedData, removed, err := bundle.StripRoots()
	if err != nil {
		s.Warn("cannot strip roots from %s: %v", f.Path, err)
		return fixrun.Skipped
	}

	if removed == 0 {
		s.OK("already clean - neither root is present (%d certificates)", before)
		return fixrun.Skipped
	}

	// Refuse if more than 2 roots would be removed (safety check)
	if removed > 2 {
		s.Bad("refusing: stripping would remove %d certificates; expected at most 2", removed)
		return fixrun.Failed
	}

	s.Say("would remove %d of %d certificates (the two roots only)", removed, before)

	// Verify the stripped copy probes correctly
	// This is the script's "test on a copy" logic (lines 2142-2149)
	tmpFile := filepath.Join(s.TempDir, "patched-bundle.pem")
	if err := os.WriteFile(tmpFile, strippedData, 0644); err != nil {
		s.Bad("cannot write temporary bundle: %v", err)
		return fixrun.Failed
	}

	// Probe the patched copy
	results, err := f.ProbeCAFile(ctx, tmpFile)
	if err != nil {
		s.Bad("test on a copy: cannot probe the patched bundle - not applying")
		return fixrun.Failed
	}

	verdict := f.Probe.Judge(results)

	switch verdict {
	case probe.VerdictRejected:
		s.OK("test on a copy: the patched bundle rejects the compromised chain")
	case probe.VerdictTrusted:
		s.Bad("test on a copy: the patched bundle STILL accepts the compromised chain - not applying")
		return fixrun.Failed
	default:
		s.Bad("could not test the patched copy (%s) - not applying a change I cannot verify", verdict)
		return fixrun.Failed
	}

	// The script's sanity_check_bundle is covered by the probe of the patched copy below: its
	// control host must still validate, so a bundle emptied by mistake is refused.

	// Warn about side effects
	s.Warn("side effect: any site whose certificate chains to either root will stop validating in tools that use this bundle")

	// Dry-run: print what would happen
	if s.DryRun {
		bak := s.BackupPath(f.Path)
		s.Say("[dry-run] would back up to %s and install the patched bundle", bak)
		s.Cmd("cp -p %s %s", f.Path, bak)
		s.Cmd("cp %s %s   # keeps owner/mode of the original", tmpFile, f.Path)
		return fixrun.Skipped
	}

	// Confirm
	if !s.Confirm(fmt.Sprintf("Remove the two roots from %s?", f.Path)) {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Check if we need root
	needsRoot, err := s.NeedRoot(f.Path)
	if err != nil {
		return fixrun.Failed
	}

	// Backup
	bak, err := s.Backup(ctx, f.Path)
	if err != nil {
		s.Bad("backup failed - nothing changed")
		return fixrun.Failed
	}

	// Install the patched bundle
	// Use cp to preserve owner and mode
	if needsRoot {
		if err := s.AsRoot(ctx, "cp", tmpFile, f.Path); err != nil {
			s.Bad("install failed - restoring")
			_ = s.Restore(ctx, bak, f.Path)
			return fixrun.Failed
		}
	} else {
		// Atomic install for user-owned files:
		// 1. Get the original file's mode
		origInfo, err := os.Stat(f.Path)
		if err != nil {
			s.Bad("cannot stat %s: %v", f.Path, err)
			_ = s.Restore(ctx, bak, f.Path)
			return fixrun.Failed
		}

		// 2. Write to a temp file next to the target
		tmpInstall := f.Path + ".tmp"
		if err := os.WriteFile(tmpInstall, strippedData, 0644); err != nil {
			s.Bad("cannot write temp file: %v", err)
			_ = s.Restore(ctx, bak, f.Path)
			return fixrun.Failed
		}

		// 3. Set the mode to match the original
		if err := os.Chmod(tmpInstall, origInfo.Mode().Perm()); err != nil {
			s.Bad("cannot set mode on temp file: %v", err)
			_ = os.Remove(tmpInstall)
			_ = s.Restore(ctx, bak, f.Path)
			return fixrun.Failed
		}

		// 4. Rename over the target (atomic)
		s.Cmd("cp %s %s", tmpFile, f.Path)
		if err := os.Rename(tmpInstall, f.Path); err != nil {
			s.Bad("install failed - restoring")
			_ = os.Remove(tmpInstall)
			_ = s.Restore(ctx, bak, f.Path)
			return fixrun.Failed
		}
	}

	// Verify the installed bundle
	// This is the script's verification step (lines 2173-2181)
	results, err = f.ProbeCAFile(ctx, f.Path)
	if err != nil {
		s.Bad("verification failed (cannot probe) - rolling back")
		_ = s.Restore(ctx, bak, f.Path)
		return fixrun.Failed
	}

	verdict = f.Probe.Judge(results)
	switch verdict {
	case probe.VerdictRejected:
		s.OK("verified: %s now rejects the compromised chain", f.Path)
		s.Note("%s  ->  %s", f.Path, bak)
		return fixrun.Changed
	default:
		s.Bad("verification failed (%s) - rolling back", verdict)
		_ = s.Restore(ctx, bak, f.Path)
		return fixrun.Failed
	}
}

// Undo restores the newest backups for system CA bundles.
// Ports the sysbundle part of run_undo from the bash script (lines 3139-3193).
func (k *Kind) Undo(ctx context.Context, env *kinds.Env, s *fixrun.Session) error {
	// Find backups for common bundle paths
	candidates := []string{
		"/etc/ssl/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/ca-bundle.pem",
		"/usr/local/share/certs/ca-root-nss.crt",
	}

	any := false
	for _, path := range candidates {
		bak := fixrun.NewestBackup(path)
		if bak == "" {
			continue
		}

		any = true
		s.Say("%s", s.Bold(path))
		s.Say("restore from %s", bak)

		if s.DryRun {
			s.Say("[dry-run] would restore it")
			continue
		}

		if !s.Confirm(fmt.Sprintf("Restore %s from that backup?", path)) {
			s.Say("skipped")
			continue
		}

		needsRoot, err := s.NeedRoot(path)
		if err != nil {
			continue
		}

		if needsRoot {
			if err := s.AsRoot(ctx, "cp", "-p", bak, path); err != nil {
				s.Bad("restore failed")
				continue
			}
		} else {
			s.Cmd("cp -p %s %s", bak, path)
			if err := s.Restore(ctx, bak, path); err != nil {
				s.Bad("restore failed")
				continue
			}
		}

		s.OK("restored")
	}

	if !any {
		s.Say("  No %s backups found in the usual places.", fixrun.BackupTag)
	}

	return nil
}

// AbsentText implements kinds.Absent.
func (k *Kind) AbsentText(*kinds.Env) string { return "none found" }

// SectionNote implements kinds.SectionNoter: on macOS the Keychain already carries Apple's block,
// which the file probes above do not see.
func (k *Kind) SectionNote(env *kinds.Env) string {
	if env.Host.OS != "darwin" {
		return ""
	}
	return "Note: macOS's own trust store (Keychain) carries Apple's block since 19 Oct; tools that use it are protected."
}
