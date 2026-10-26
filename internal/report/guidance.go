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

package report

import (
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
)

// SystemGuidance returns the shared "System trust store" block for a host. It
// ports print_sys_guidance(). Kinds do not carry this text: a Kind whose tool
// reads the OS CA bundle sets Finding.NeedsSystemGuidance, and the report
// prints this block once, however many findings asked for it.
func SystemGuidance(h platform.Host) []string {
	lines := []string{
		"  System trust store (for tools that read the OS CA bundle)",
		"    Preferred: install your OS vendor's fixed CA package/update. If none is available yet, the page's",
		"    workaround distrusts the two roots the compromised intermediates chain to ('AAA Certificate",
		"    Services' by Comodo, and 'emSign ECC Root CA - G3'). That can break legitimate sites which chain",
		"    to those roots, so keep the backup, test, and re-run this audit afterwards.",
		"",
	}
	all := h.Distro.ID + " " + h.Distro.IDLike + " " + osName(h)
	switch {
	case strings.Contains(all, "Darwin"):
		lines = append(lines, darwinGuidance()...)
	case strings.Contains(all, "alpine"):
		lines = append(lines, alpineGuidance()...)
	case strings.Contains(all, "debian") || strings.Contains(all, "ubuntu") || strings.Contains(all, "devuan"):
		lines = append(lines, debianGuidance()...)
	case strings.Contains(all, "fedora") || strings.Contains(all, "rhel") || strings.Contains(all, "centos") ||
		strings.Contains(all, "rocky") || strings.Contains(all, "almalinux") || strings.Contains(all, "amzn"):
		lines = append(lines, redhatGuidance()...)
	case strings.Contains(all, "suse") || strings.Contains(all, "sles"):
		lines = append(lines, suseGuidance()...)
	case strings.Contains(all, "arch"):
		lines = append(lines, archGuidance()...)
	case strings.Contains(all, "nixos"):
		lines = append(lines, nixosGuidance()...)
	case strings.Contains(all, "FreeBSD"):
		lines = append(lines, freebsdGuidance()...)
	case strings.Contains(all, "NetBSD"):
		lines = append(lines, netbsdGuidance()...)
	default:
		lines = append(lines, "    No recipe for this platform here - see https://emudhra.we-have-a-problem.com/ .")
	}
	return append(lines, "")
}

// osName is uname -s for the host, which the script matches against.
func osName(h platform.Host) string {
	switch h.OS {
	case "darwin":
		return "Darwin"
	case "linux":
		return "Linux"
	case "freebsd":
		return "FreeBSD"
	case "netbsd":
		return "NetBSD"
	}
	return h.OS
}

// PipGuidance returns the shared "Built-in pip (macOS)" block, a port of
// print_pip_guidance().
func PipGuidance() []string {
	return []string{
		"  Built-in pip (macOS)",
		"    Apple's pip does its own certificate handling; the page's fix points it at the system bundle.",
		"    Do this after the System trust store workaround above:",
		`      F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py" &&`,
		`      echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null &&`,
		`      sudo chmod 644 "$F"`,
		"",
		"    Alternatively avoid Apple's python3/pip: use Homebrew Python or a virtualenv with pip >= 26.2.2.",
		"",
	}
}

// darwinGuidance returns macOS-specific guidance.
func darwinGuidance() []string {
	return []string{
		"    macOS - /etc/ssl/cert.pem (read by the built-in curl, git, python3, perl, ruby, openssl):",
		"      sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak &&",
		"      sudo awk '/^(###|===) /{skip=0}",
		"        /^=== .*\\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}",
		"        !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null",
		"      (An OS update may replace this file. Others report that macOS updates do not refresh it, so re-run",
		"       the audit after updating rather than assuming either way.)",
	}
}

// alpineGuidance returns Alpine-specific guidance.
func alpineGuidance() []string {
	return []string{
		"    Alpine:",
		"      apk add ca-certificates &&",
		"      sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates",
	}
}

// debianGuidance returns Debian/Ubuntu-specific guidance.
func debianGuidance() []string {
	return []string{
		"    Debian / Ubuntu (run as root):",
		"      sed -i \\",
		"        -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \\",
		"        -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \\",
		"        /etc/ca-certificates.conf && update-ca-certificates",
	}
}

// redhatGuidance returns Fedora/RHEL/CentOS-specific guidance.
func redhatGuidance() []string {
	return []string{
		"    Fedora / RHEL / CentOS / Rocky / Alma / Amazon Linux 2023 (run as root):",
		"      d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist",
		"      trust extract --overwrite --format=pem-bundle \\",
		"        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \\",
		"        $d/Comodo_AAA_Services_root.pem &&",
		"      trust extract --overwrite --format=pem-bundle \\",
		"        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \\",
		"        $d/emSign_ECC_Root_CA_-_G3.pem &&",
		"      update-ca-trust",
	}
}

// suseGuidance returns openSUSE/SLES-specific guidance.
func suseGuidance() []string {
	return []string{
		"    openSUSE / SLES (run as root):",
		"      d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist",
		"      trust extract --format=pem-bundle \\",
		"        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \\",
		"        $d/Comodo_AAA_Services_root.pem &&",
		"      trust extract --format=pem-bundle \\",
		"        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \\",
		"        $d/emSign_ECC_Root_CA_-_G3.pem &&",
		"      update-ca-certificates",
	}
}

// archGuidance returns Arch Linux-specific guidance.
func archGuidance() []string {
	return []string{
		"    Arch Linux (run as root):",
		"      trust extract --format=pem-bundle \\",
		"        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \\",
		"        /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem &&",
		"      update-ca-trust",
	}
}

// nixosGuidance returns NixOS-specific guidance.
func nixosGuidance() []string {
	return []string{
		"    NixOS (configuration.nix):",
		"      security.pki.caCertificateBlacklist = [ \"Comodo AAA Services root\" \"emSign ECC Root CA - G3\" ];",
	}
}

// freebsdGuidance returns FreeBSD-specific guidance.
func freebsdGuidance() []string {
	return []string{
		"    FreeBSD 14+ (run as root):",
		"      cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem",
		"      cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem",
		"      certctl rehash",
	}
}

// netbsdGuidance returns NetBSD-specific guidance.
func netbsdGuidance() []string {
	return []string{
		"    NetBSD 10+ (run as root):",
		"      certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem &&",
		"      certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem",
	}
}

func (r *Reporter) prog() string {
	if r.ProgName != "" {
		return r.ProgName
	}
	return "emudhra-audit-fix"
}

// firstFix is the compact line for an item: the Kind's compact guidance, or
// the first full line with "... (-v for the rest)" when there are several,
// as the script's first_fix.
func firstFix(f kinds.Finding) string {
	if f.GuidanceCompact != "" {
		return f.GuidanceCompact
	}
	if len(f.GuidanceFull) == 0 {
		return "(no specific guidance - see https://emudhra.we-have-a-problem.com/)"
	}
	first := strings.TrimLeft(f.GuidanceFull[0], " ")
	if len(f.GuidanceFull) > 1 {
		first += " ... (-v for the rest)"
	}
	return first
}

func (r *Reporter) renderGuidance(findings []kinds.Finding) {
	var fix, advise []kinds.Finding
	needSys, needPip, anyFix := false, false, false
	for _, f := range findings {
		switch {
		case f.Status().IsBad():
			fix = append(fix, f)
			needSys = needSys || f.NeedsSystemGuidance
			needPip = needPip || f.NeedsPipGuidance
		case f.BehindButProtected():
			advise = append(advise, f)
		}
		anyFix = anyFix || (f.HasFix && f.Status().IsBad())
	}
	if len(fix) == 0 && len(advise) == 0 {
		return
	}
	if r.Verbose < 1 {
		r.renderCompactGuidance(fix, advise, needSys, anyFix)
		return
	}
	r.printf("%s== Remediation guidance ==%s\n", r.c(cBld), r.c(cOff))
	if r.FixMode {
		r.printf("  This is guidance only; nothing below has been run yet. Commands that edit system trust\n")
	} else {
		r.printf("  This is guidance only; nothing below has been run. Commands that edit system trust\n")
	}
	r.printf("  files need sudo - read them first. Upgrading is better than distrusting roots where it is possible.\n\n")
	if len(fix) > 0 {
		r.printf("%s%sAffected - fix these first%s\n", r.c(cBld), r.c(cRed), r.c(cOff))
		for _, f := range fix {
			r.fullEntry(f)
		}
		if needSys {
			r.printLines(SystemGuidance(r.Host))
		}
		if needPip {
			r.printLines(PipGuidance())
		}
	}
	if len(advise) > 0 {
		r.printf("%s%sProtected today, but older than the fixed release - upgrade when convenient%s\n", r.c(cBld), r.c(cYel), r.c(cOff))
		for _, f := range advise {
			r.fullEntry(f)
		}
	}
	if !r.FixMode && anyFix {
		r.printf("  This script can apply some of these for you (system CA bundle, Java cacerts, Homebrew, macOS pip):\n")
		r.printf("    %s --fix --dry-run    # verify and show every step, change nothing\n", r.prog())
		r.printf("    %s --fix              # apply, asking before each change\n\n", r.prog())
	}
	r.printf("  After changing anything, re-run this script to confirm.\n\n")
}

func (r *Reporter) fullEntry(f kinds.Finding) {
	r.printf("  - %s %s\n    %s\n", f.Tool, f.Version, f.Path)
	if len(f.GuidanceFull) == 0 {
		r.printf("      (no specific guidance - see https://emudhra.we-have-a-problem.com/)\n\n")
		return
	}
	// The script's `fix "text"` prints each line indented 6 spaces, and each entry is followed
	// by a blank line. Kinds supply the text; the layout is the report's.
	for _, l := range f.GuidanceFull {
		r.printf("      %s\n", strings.TrimLeft(l, " "))
	}
	r.printf("\n")
}

func (r *Reporter) printLines(lines []string) {
	for _, l := range lines {
		r.printf("%s\n", l)
	}
}

func (r *Reporter) renderCompactGuidance(fix, advise []kinds.Finding, needSys, anyFix bool) {
	if len(fix) > 0 {
		r.printf("%s%sFix first%s (nothing has been run; -v shows full commands)\n", r.c(cBld), r.c(cRed), r.c(cOff))
		for _, f := range fix {
			r.printf("  - %s %s: %s\n", f.Tool, f.Version, firstFix(f))
		}
		if needSys {
			r.printf("  - System CA bundle: upgrade your OS CA package, or distrust the two roots (recipe for this platform with -v)\n")
		}
		r.printf("\n")
	}
	if len(advise) > 0 {
		r.printf("%s%sProtected, but older than the fixed release%s\n", r.c(cBld), r.c(cYel), r.c(cOff))
		for _, f := range advise {
			r.printf("  - %s %s: %s\n", f.Tool, f.Version, firstFix(f))
		}
		r.printf("\n")
	}
	if !r.FixMode && anyFix {
		r.printf("Apply fixes: %s --fix --dry-run   (shows every step, changes nothing), then --fix\n\n", r.prog())
	}
}
