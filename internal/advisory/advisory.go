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

// Package advisory holds the two roots to distrust and the fixed-version table.
// This is the single source of truth for remediation version requirements.
package advisory

import (
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// The two roots that must be distrusted per the eMudhra advisory.
const (
	RootAAACertificateServices = "AAA Certificate Services"
	RootEmSignECCRootCAG3      = "emSign ECC Root CA - G3"
)

// IsRootToDistrust returns true if the given subject is one of the two roots
// that must be distrusted.
func IsRootToDistrust(subject string) bool {
	// Normalize whitespace and check both roots
	s := strings.Join(strings.Fields(subject), " ")
	return s == RootAAACertificateServices || s == RootEmSignECCRootCAG3
}

// FixedVersion represents a minimum fixed version for a tool.
type FixedVersion struct {
	Tool    string // Tool name (e.g., "node", "rustup", "uv")
	Version string // Minimum fixed version as string
	Notes   string // Additional notes or documentation
}

// FixedVersions is the canonical table of fixed versions per tool.
// These were taken from https://emudhra.we-have-a-problem.com/ as of 2026-10-22.
// Check the page for updates.
var FixedVersions = []FixedVersion{
	// Node.js
	{Tool: "node", Version: "22.23.4", Notes: "Node.js 22.x fixed in 22.23.4"},
	{Tool: "node", Version: "24.22.1", Notes: "Node.js 24.x fixed in 24.22.1"},
	{Tool: "node", Version: "26.12.1", Notes: "Node.js 26.x fixed in 26.12.1"},

	// Deno
	{Tool: "deno", Version: "2.9.8", Notes: "Deno fixed in 2.9.8"},

	// Go
	{Tool: "golang", Version: "1.26.10", Notes: "Go fixed in 1.26.10 and 1.27.3"},
	{Tool: "golang", Version: "1.27.3", Notes: "Go fixed in 1.26.10 and 1.27.3"},

	// Java (JDK/JRE)
	{Tool: "java", Version: "8u511", Notes: "Java 8 fixed in 8u511"},
	{Tool: "java", Version: "11.0.33", Notes: "Java 11 fixed in 11.0.33"},
	{Tool: "java", Version: "17.0.21", Notes: "Java 17 fixed in 17.0.21"},
	{Tool: "java", Version: "21.0.13", Notes: "Java 21 fixed in 21.0.13"},
	{Tool: "java", Version: "25.0.5", Notes: "Java 25 fixed in 25.0.5"},
	{Tool: "java", Version: "27.0.1", Notes: "Java 27 fixed in 27.0.1"},

	// Python packages
	{Tool: "certifi", Version: "2026.10.19", Notes: "certifi fixed in 2026.10.19"},
	{Tool: "pip", Version: "26.2.2", Notes: "pip fixed in 26.2.2"},

	// Rust
	{Tool: "rustup", Version: "1.29.2", Notes: "rustup fixed in 1.29.2"},

	// uv
	{Tool: "uv", Version: "0.13.4", Notes: "uv fixed in 0.13.4"},

	// Other version-only tools
	{Tool: "pixi", Version: "0.82.1", Notes: "pixi fixed in 0.82.1"},
	{Tool: "mise", Version: "2026.10.17", Notes: "mise fixed in 2026.10.17"},
	{Tool: "claude", Version: "2.1.303", Notes: "Claude Code fixed in 2.1.303"},

	// Homebrew ca-certificates (not a semver: a date with a revision)
	{Tool: "brew-ca-certificates", Version: "2026-09-25_1", Notes: "Homebrew ca-certificates fixed in 2026-09-25_1"},

	// Bun - pending
	// {Tool: "bun", Version: "", Notes: "Bun fix pending per advisory"},
}

// GetFixedVersions returns all fixed versions for a given tool.
func GetFixedVersions(tool string) []FixedVersion {
	var result []FixedVersion
	for _, fv := range FixedVersions {
		if fv.Tool == tool && fv.Version != "" {
			result = append(result, fv)
		}
	}
	return result
}

// IsFixed checks if the given version meets or exceeds ANY fixed version for the tool.
func IsFixed(tool, ver string) bool {
	v := version.Parse(ver)
	fixedVersions := GetFixedVersions(tool)
	if len(fixedVersions) == 0 {
		// Unknown tools have no fixed version
		return false
	}
	for _, fv := range fixedVersions {
		if v.GE(version.Parse(fv.Version)) {
			return true
		}
	}
	// The version is below ALL fixed versions for this tool
	return false
}

// IsAffected returns true if the version is below all fixed versions for the tool.
// Returns false for unknown tools (no fixed version = can't determine affected status).
func IsAffected(tool, ver string) bool {
	// Unknown tools have no fixed versions
	if len(GetFixedVersions(tool)) == 0 {
		return false
	}
	return !IsFixed(tool, ver) && ver != ""
}

// LineCheck is the result of checking a version against a tool that is fixed
// per release line (Go, Node.js, Java). It mirrors the script's VC/VN/FIXV
// triple for those tools.
type LineCheck struct {
	Check string // "ok", "behind" or "nofix"
	Fixed string // the fixed release for this line, or a description when none
	Note  string // text for the version note, e.g. "fixed in 1.26.10"
}

// GoLineCheck ports check_go_version(). Fixes exist only for the 1.26 and
// 1.27 lines; anything older has no fix, and 1.28 or newer is past the fixed
// lines. ok is false when the version cannot be parsed.
func GoLineCheck(ver string) (LineCheck, bool) {
	v := leadingVersion(ver)
	if v == "" {
		return LineCheck{}, false
	}
	pv := version.Parse(v)
	fixFor := func(fix string) LineCheck {
		if pv.GE(version.Parse(fix)) {
			return LineCheck{Check: "ok", Fixed: fix, Note: "fixed in " + fix}
		}
		return LineCheck{Check: "behind", Fixed: fix, Note: "fixed in " + fix}
	}
	switch {
	case v == "1.27" || strings.HasPrefix(v, "1.27."):
		return fixFor("1.27.3"), true
	case v == "1.26" || strings.HasPrefix(v, "1.26."):
		return fixFor("1.26.10"), true
	}
	if pv.GE(version.Parse("1.28")) {
		return LineCheck{Check: "ok", Note: "newer than the fixed lines (1.26.10, 1.27.3)"}, true
	}
	return LineCheck{Check: "nofix", Fixed: "1.26.10 or 1.27.3", Note: "fixes only published for 1.26.10 and 1.27.3"}, true
}

// leadingVersion keeps the leading run of digits and dots, as the script's
// ${v%%[!0-9.]*}.
func leadingVersion(s string) string {
	for i, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return s[:i]
		}
	}
	return s
}
