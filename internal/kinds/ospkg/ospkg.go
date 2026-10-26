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

// Package ospkg audits and patches OS CA packages.
// It ports audit_ospkg, fix_debian_like, and fix_p11_blocklist from the bash script.
package ospkg

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// SectionTitle is the audit_start title for OS CA packages, shown in verbose mode.
const SectionTitle = "OS CA packages"

// Kind implements the audit for OS CA packages.
// It checks version of ca-certificates package for dpkg (Debian/Ubuntu),
// apk (Alpine), pacman (Arch), and rpm (Fedora). Other rpm distros are
// reported without a verdict.
type Kind struct{}

// New creates a new ospkg Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier.
func (k *Kind) ID() string {
	return "ospkg"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "OS CA packages (ca-certificates)"
}

// Applicable reports whether this Kind makes sense on this host.
// Linux only: returns false on darwin with reason.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	if h.OS != "linux" {
		return kinds.Applicability{
			Applies: false,
			Reason:  "Linux only",
		}
	}
	return kinds.Applicability{Applies: true}
}

// Audit discovers OS CA packages and returns findings.
// It uses the Runner to query package managers and checks versions
// against fixed versions for each distribution.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	// Try each package manager in order (matching the script's logic)
	if k.checkDPKG(ctx, env, &findings) {
		return findings, nil
	}
	if k.checkAPK(ctx, env, &findings) {
		return findings, nil
	}
	if k.checkPacman(ctx, env, &findings) {
		return findings, nil
	}
	if k.checkRPM(ctx, env, &findings) {
		return findings, nil
	}

	// No supported package manager found
	return findings, nil
}

// dpkgCompareVersions compares two Debian package versions.
// It prefers to use the actual dpkg --compare-versions command when available,
// but falls back to a pure-Go implementation when dpkg is not present.
func dpkgCompareVersions(ctx context.Context, env *kinds.Env, ver, op, fixed string) bool {
	// Try using real dpkg --compare-versions if available
	result := env.Run.Run(ctx, "dpkg", "--compare-versions", ver, op, fixed)
	if result.Error == nil {
		return result.ExitCode == 0
	}

	// Fallback to pure-Go implementation when dpkg is not available
	// This handles the most common cases but is not complete Debian version ordering
	return dpkgCompareVersionsGo(ver, op, fixed)
}

// dpkgCompareVersionsGo implements a subset of Debian version comparison in pure Go.
// It handles the common cases: epochs, tilde, plus, and date-style versions.
// It does NOT implement the full dpkg algorithm; for accuracy, ensure dpkg is available.
func dpkgCompareVersionsGo(a, op, b string) bool {
	cmp := compareDebianVersions(a, b)
	switch op {
	case "ge":
		return cmp >= 0
	case "gt":
		return cmp > 0
	case "le":
		return cmp <= 0
	case "lt":
		return cmp < 0
	case "eq":
		return cmp == 0
	default:
		return false
	}
}

// compareDebianVersions compares two Debian version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareDebianVersions(a, b string) int {
	// Handle epochs
	aEpoch, aRest := extractEpoch(a)
	bEpoch, bRest := extractEpoch(b)

	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1
		}
		return 1
	}

	// Split into upstream and revision
	aUpstream, aRevision := splitDebianVersion(aRest)
	bUpstream, bRevision := splitDebianVersion(bRest)

	// Compare upstream versions
	cmp := compareDebianParts(aUpstream, bUpstream)
	if cmp != 0 {
		return cmp
	}

	// Compare revisions
	return compareDebianParts(aRevision, bRevision)
}

// extractEpoch extracts the epoch from a Debian version string.
// Returns (epoch, rest).
func extractEpoch(v string) (int, string) {
	if idx := strings.Index(v, ":"); idx >= 0 {
		epoch, err := strconv.Atoi(v[:idx])
		if err != nil {
			return 0, v
		}
		return epoch, v[idx+1:]
	}
	return 0, v
}

// splitDebianVersion splits a Debian version into upstream and revision.
func splitDebianVersion(v string) (string, string) {
	if idx := strings.LastIndex(v, "-"); idx >= 0 {
		return v[:idx], v[idx+1:]
	}
	return v, ""
}

// compareDebianParts compares two Debian version components.
func compareDebianParts(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		// Extract leading non-digit and digit portions
		aNonDigit, aRest := extractNonDigit(a)
		bNonDigit, bRest := extractNonDigit(b)

		cmp := compareDebianNonDigit(aNonDigit, bNonDigit)
		if cmp != 0 {
			return cmp
		}

		aDigit, aRest := extractDigit(aRest)
		bDigit, bRest := extractDigit(bRest)

		if aDigit != bDigit {
			if aDigit < bDigit {
				return -1
			}
			return 1
		}

		a = aRest
		b = bRest
	}
	return 0
}

// extractNonDigit extracts the leading non-digit characters from a string.
func extractNonDigit(s string) (string, string) {
	i := 0
	for i < len(s) && !isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// extractDigit extracts the leading digit characters from a string.
func extractDigit(s string) (int, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == 0 {
		return 0, s
	}
	val, _ := strconv.Atoi(s[:i])
	return val, s[i:]
}

// isDigit returns true if b is an ASCII digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// compareDebianNonDigit compares non-digit portions of Debian versions.
// Tilde (~) sorts before everything, even empty string.
func compareDebianNonDigit(a, b string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		ca := a[i]
		cb := b[i]

		// Tilde sorts before everything
		if ca == '~' && cb != '~' {
			return -1
		}
		if cb == '~' && ca != '~' {
			return 1
		}

		// Compare characters
		if ca < cb {
			return -1
		}
		if ca > cb {
			return 1
		}
	}

	// Tilde before end
	if len(a) < len(b) && b[len(a)] == '~' {
		return 1
	}
	if len(b) < len(a) && a[len(b)] == '~' {
		return -1
	}

	// Longer string is greater (unless trailing tilde)
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}

	return 0
}

// checkDPKG checks Debian/Ubuntu ca-certificates via dpkg-query.
// Returns true if dpkg is available and the package is installed.
func (k *Kind) checkDPKG(ctx context.Context, env *kinds.Env, findings *[]kinds.Finding) bool {
	// Check if dpkg-query is available and the package is installed
	result := env.Run.Run(ctx, "dpkg-query", "-W", "ca-certificates")
	if result.Error != nil || result.ExitCode != 0 {
		return false
	}

	// Get the version
	ver := ""
	result = env.Run.Run(ctx, "dpkg-query", "-W", "-f=${Version}", "ca-certificates")
	if result.Error == nil && result.ExitCode == 0 {
		ver = strings.TrimSpace(result.Stdout)
	}

	// Determine distro and fixed version (script lines 1663-1666)
	fixed := ""
	id := env.Host.Distro.ID
	vid := env.Host.Distro.Version

	switch id {
	case "ubuntu":
		switch vid {
		case "22.04", "24.04", "26.04", "26.10":
			fixed = fmt.Sprintf("20260816ubuntu0.%s.1", vid)
		}
	case "debian":
		switch vid {
		case "12":
			fixed = "20250419~deb12u2"
		case "13":
			fixed = "20250419+deb13u1"
		default:
			fixed = "20260816+nmu1"
		}
	}

	// Compare versions (line 1667)
	vc := kinds.VersionUnknown
	vn := ""
	if fixed != "" && ver != "" {
		// Use dpkg --compare-versions through the runner
		if dpkgCompareVersions(ctx, env, ver, "ge", fixed) {
			vc = kinds.VersionOK
		} else {
			vc = kinds.VersionBehind
		}
		vn = fmt.Sprintf("fixed in %s", fixed)
	}

	// Build upgrade command (line 1661)
	upg := "sudo apt-get update && sudo apt-get install --only-upgrade ca-certificates"

	// Build finding
	finding := kinds.NewFinding("ospkg", "ca-certificates (dpkg)")
	finding.Path = "dpkg"
	finding.SetProbe(kinds.ProbeSkipped, "skipped:package check only; see the CA bundle results above")
	finding.SetVersion(ver, fixed, vc, vn)

	if vc == kinds.VersionBehind {
		finding.AddGuidance(
			upg,
			upg,
			"If your distribution has not shipped the fix yet, use the workaround in System trust store (below).",
		)
		finding.HasFix = true
		// audit_ospkg: FIXSYS=1, which plans the host-wide system trust store fix.
		finding.NeedsSystemGuidance = true
	}

	*findings = append(*findings, finding)
	return true
}

// checkAPK checks Alpine ca-certificates via apk.
// Returns true if apk is available and the package is installed.
func (k *Kind) checkAPK(ctx context.Context, env *kinds.Env, findings *[]kinds.Finding) bool {
	// Check if apk is available and package is installed (lines 1670-1671)
	result := env.Run.Run(ctx, "apk", "info", "-e", "ca-certificates")
	if result.Error != nil || result.ExitCode != 0 {
		return false
	}

	// Get the version (line 1671)
	ver := ""
	result = env.Run.Run(ctx, "apk", "list", "-I", "ca-certificates")
	if result.Error == nil && result.ExitCode == 0 {
		// Parse: "ca-certificates-20261020-r0 x86_64 {alpine}"
		lines := strings.Split(result.Stdout, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ca-certificates-") {
				// Extract version before the first space
				if idx := strings.Index(line, " "); idx > 0 {
					prefix := line[:idx] // "ca-certificates-20261020-r0"
					ver = strings.TrimPrefix(prefix, "ca-certificates-")
				}
				break
			}
		}
	}

	// Fixed version for Alpine (line 1672)
	fixed := "20261020-r0"

	// Compare versions (lines 1673-1676)
	vc := kinds.VersionUnknown
	vn := fmt.Sprintf("fixed in %s", fixed)

	if ver != "" {
		// Extract numeric part (before -r)
		verNum := ver
		if idx := strings.Index(ver, "-r"); idx >= 0 {
			verNum = ver[:idx]
		}

		// Alpine version comparison: simple numeric comparison of date
		if verNum != "" && isAllDigits(verNum) {
			verDate, err1 := strconv.Atoi(verNum)
			fixedDate := 20261020
			if err1 == nil && verDate >= fixedDate {
				vc = kinds.VersionOK
			} else if err1 == nil {
				vc = kinds.VersionBehind
			}
		}
	}

	// Build upgrade command (line 1672)
	upg := "apk update && apk upgrade ca-certificates"

	// Build finding
	finding := kinds.NewFinding("ospkg", "ca-certificates (apk)")
	finding.Path = "apk"
	finding.SetProbe(kinds.ProbeSkipped, "skipped:package check only; see the CA bundle results above")
	finding.SetVersion(ver, fixed, vc, vn)

	if vc == kinds.VersionBehind {
		finding.AddGuidance(
			upg,
			upg,
			"If your distribution has not shipped the fix yet, use the workaround in System trust store (below).",
		)
		finding.HasFix = true
		// audit_ospkg: FIXSYS=1, which plans the host-wide system trust store fix.
		finding.NeedsSystemGuidance = true
	}

	*findings = append(*findings, finding)
	return true
}

// checkPacman checks Arch ca-certificates-mozilla via pacman.
// Returns true if pacman is available and the package is installed.
func (k *Kind) checkPacman(ctx context.Context, env *kinds.Env, findings *[]kinds.Finding) bool {
	// Check if pacman is available and package is installed (line 1678)
	result := env.Run.Run(ctx, "pacman", "-Q", "ca-certificates-mozilla")
	if result.Error != nil || result.ExitCode != 0 {
		return false
	}

	// Get the version (line 1678)
	ver := ""
	result = env.Run.Run(ctx, "pacman", "-Q", "ca-certificates-mozilla")
	if result.Error == nil && result.ExitCode == 0 {
		// Output: "ca-certificates-mozilla 3.131.1-1"
		fields := strings.Fields(strings.TrimSpace(result.Stdout))
		if len(fields) >= 2 {
			ver = fields[1]
		}
	}

	// Fixed version for Arch (line 1679)
	fixed := "3.131.1-1"

	// Compare versions (line 1680)
	// Arch versions: 3.131.1-1, compare prefix before dash
	vc := kinds.VersionUnknown
	vn := fmt.Sprintf("fixed in %s", fixed)

	if ver != "" {
		// Extract version before the dash
		verNum := ver
		if idx := strings.Index(ver, "-"); idx >= 0 {
			verNum = ver[:idx]
		}

		// Compare the numeric portion using version.Parse
		if version.Parse(verNum).GE(version.Parse("3.131.1")) {
			vc = kinds.VersionOK
		} else {
			vc = kinds.VersionBehind
		}
	}

	// Build upgrade command (line 1679)
	upg := "sudo pacman -Syu ca-certificates-mozilla"

	// Build finding
	finding := kinds.NewFinding("ospkg", "ca-certificates (pacman)")
	finding.Path = "pacman"
	finding.SetProbe(kinds.ProbeSkipped, "skipped:package check only; see the CA bundle results above")
	finding.SetVersion(ver, fixed, vc, vn)

	if vc == kinds.VersionBehind {
		finding.AddGuidance(
			upg,
			upg,
			"If your distribution has not shipped the fix yet, use the workaround in System trust store (below).",
		)
		finding.HasFix = true
		// audit_ospkg: FIXSYS=1, which plans the host-wide system trust store fix.
		finding.NeedsSystemGuidance = true
	}

	*findings = append(*findings, finding)
	return true
}

// checkRPM checks Fedora/RHEL ca-certificates via rpm.
// Returns true if rpm is available and the package is installed.
// Only Fedora gets a verdict; other rpm distros are reported without one.
func (k *Kind) checkRPM(ctx context.Context, env *kinds.Env, findings *[]kinds.Finding) bool {
	// Check if rpm is available and package is installed (line 1682)
	result := env.Run.Run(ctx, "rpm", "-q", "ca-certificates")
	if result.Error != nil || result.ExitCode != 0 {
		return false
	}

	// Get the version (line 1682)
	ver := ""
	result = env.Run.Run(ctx, "rpm", "-q", "--qf=%{VERSION}", "ca-certificates")
	if result.Error == nil && result.ExitCode == 0 {
		ver = strings.TrimSpace(result.Stdout)
	}

	// Determine verdict based on distro (lines 1684-1690)
	vc := kinds.VersionUnknown
	var fixed string
	var vn string

	id := env.Host.Distro.ID

	if id == "fedora" {
		// Fedora has a fixed version (line 1685)
		fixed = "2026.2.92_v9.0.319"

		// Fedora versions look like 2026.2.92_v9.0.319
		// Compare date-like part, then _v build part (lines 1686-1687)
		if ver != "" {
			verBase := ver
			verBuild := ""
			if idx := strings.Index(ver, "_v"); idx >= 0 {
				verBase = ver[:idx]
				verBuild = ver[idx+2:]
			}

			fixedBase := "2026.2.92"
			fixedBuild := "9.0.319"

			verBaseParsed := version.Parse(verBase)
			fixedBaseParsed := version.Parse(fixedBase)

			// Compare: if base greater, it's OK; if equal, compare build
			if verBaseParsed.Compare(fixedBaseParsed) > 0 {
				vc = kinds.VersionOK
			} else if verBaseParsed.Compare(fixedBaseParsed) == 0 && version.Parse(verBuild).GE(version.Parse(fixedBuild)) {
				vc = kinds.VersionOK
			} else {
				vc = kinds.VersionBehind
			}
		}
		vn = fmt.Sprintf("fixed in %s", fixed)
	} else {
		// Other rpm distros: no fixed version listed (lines 1688-1689)
		vn = "the page lists no fixed package for this distribution"
		// vc remains VersionUnknown, fixed remains empty
		// This will result in Status Unknown after SetVersion
	}

	// Build upgrade command (line 1683)
	upg := "sudo dnf upgrade ca-certificates"

	// Build finding
	finding := kinds.NewFinding("ospkg", "ca-certificates (rpm)")
	finding.Path = "rpm"
	finding.SetProbe(kinds.ProbeSkipped, "skipped:package check only; see the CA bundle results above")
	finding.SetVersion(ver, fixed, vc, vn)

	if vc == kinds.VersionBehind {
		finding.AddGuidance(
			upg,
			upg,
			"If your distribution has not shipped the fix yet, use the workaround in System trust store (below).",
		)
		finding.HasFix = true
		// audit_ospkg: FIXSYS=1, which plans the host-wide system trust store fix.
		finding.NeedsSystemGuidance = true
	}

	*findings = append(*findings, finding)
	return true
}

// isAllDigits checks if a string contains only digits.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Plan returns fixes for affected OS packages.
// Ports fix_debian_like and fix_p11_blocklist from the bash script.
// FixOrder implements kinds.Fixer: where the system store fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixSys }

func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	// The script plans ONE host-wide system trust store fix (plan_add sys system)
	// when any bad finding asks for it, then fix_system picks the method from the
	// host. This Kind owns the Linux methods; sysbundle owns macOS.
	if env.Host.OS != "linux" || !kinds.WantsSystemFix(findings) {
		return nil, nil
	}
	all := env.Host.Distro.ID + " " + env.Host.Distro.IDLike
	switch {
	case containsAny(all, "debian", "ubuntu", "alpine", "devuan"):
		return []fixrun.Fix{&DebianLikeFix{
			WorkaroundOnly: env.WorkaroundOnly,
			DistroID:       env.Host.Distro.ID,
			DistroVersion:  env.Host.Distro.Version,
			Paths:          Paths{PathEnv: env.Path()},
		}}, nil
	case containsAny(all, "fedora", "rhel", "centos", "rocky", "almalinux", "amzn", "suse", "sles", "arch"):
		return []fixrun.Fix{&P11BlocklistFix{WorkaroundOnly: env.WorkaroundOnly, Paths: Paths{PathEnv: env.Path()}}}, nil
	}
	// fix_system: "no automated fix for this platform" is reported by the guidance.
	return nil, nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// AbsentText implements kinds.Absent.
func (k *Kind) AbsentText(*kinds.Env) string {
	return "no supported package manager / ca-certificates package found (not applicable here)"
}
