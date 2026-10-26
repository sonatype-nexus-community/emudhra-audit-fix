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

// Package electron implements the Kind for auditing Electron apps on macOS.
// Electron apps embed the Electron runtime, which includes its own copy of Node.js
// and its own CA bundle. These cannot be probed via TLS; version check only.
package electron

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/version"
)

// SectionTitle is the audit_start title for Electron apps, shown in verbose mode.
const SectionTitle = "Electron apps"

// Kind implements kinds.Kind for Electron apps on macOS.
type Kind struct{}

// New creates a new Electron Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier "electron".
func (k *Kind) ID() string {
	return "electron"
}

// Describe returns a one-line description.
func (k *Kind) Describe() string {
	return "Electron apps (macOS)"
}

// Applicable returns true only on macOS (darwin).
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	if h.OS != "darwin" {
		return kinds.Applicability{
			Applies: false,
			Reason:  "macOS apps only for now - not checked on this platform",
		}
	}
	return kinds.Applicability{Applies: true}
}

// Audit discovers Electron apps and checks their embedded Electron versions.
// Ports audit_electron() and check_electron_version() from the legacy script.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	var findings []kinds.Finding

	home := env.Home()

	// Search patterns for Electron apps
	// Check both /Applications and ~/Applications (exactly as legacy script does)
	var patterns []string

	// Only check /Applications if not in hermetic test mode.
	// Hermetic tests have env.Environ set (non-nil), indicating they control
	// the environment completely and shouldn't find real system apps.
	// Production runs have env.Environ == nil and check both locations.
	if env.Environ == nil {
		// Check /Applications (system-wide apps) only in production
		patterns = append(patterns,
			"/Applications/*.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist",
		)
	}

	// Also check ~/Applications (user apps) if home is set
	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, "Applications/*.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"),
		)
	}

	// Track seen apps to avoid duplicates (via symlink resolution)
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		// The script's shell glob lists apps the way the user's locale collates them: ignoring
		// case, so "balenaEtcher" comes before "Bitwarden". Go sorts bytes, so do it explicitly.
		slices.SortStableFunc(matches, func(a, b string) int {
			return strings.Compare(strings.ToLower(a), strings.ToLower(b))
		})

		for _, plistPath := range matches {
			// Extract app path from plist path
			// plistPath: /path/to/App.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist
			appPath := extractAppPath(plistPath)
			if appPath == "" {
				continue
			}

			// Resolve symlinks to dedupe
			resolvedApp, err := filepath.EvalSymlinks(appPath)
			if err != nil {
				resolvedApp = appPath
			}

			// Skip if already seen
			if seen[resolvedApp] {
				continue
			}
			seen[resolvedApp] = true

			// Extract app name
			appName := filepath.Base(appPath)
			appName = strings.TrimSuffix(appName, ".app")

			// Read Electron version from Info.plist
			electronVersion, err := readPlistVersion(plistPath, env)
			if err != nil {
				env.Log.Debug("Failed to read Electron version", "app", appName, "error", err)
				continue
			}

			// Check version against fixed versions
			check := checkElectronVersion(electronVersion)

			// Create finding
			// Tool name format: "Electron app: <AppName>" (script line 1742)
			// Version format: "Electron <version>" (script line 1742: "Electron ${v:-?}")
			toolName := fmt.Sprintf("Electron app: %s", appName)
			versionDisplay := fmt.Sprintf("Electron %s", electronVersion)

			finding := kinds.NewFinding(k.ID(), toolName)
			finding.Path = appPath
			finding.Version = versionDisplay

			// Set probe result - skipped because we cannot probe embedded runtimes
			finding.SetProbe(kinds.ProbeSkipped, "cannot probe an app's embedded runtime - version check only")

			// Set version check and derive status
			// Use versionDisplay format (with "Electron " prefix) for the version field
			switch check.status {
			case statusBehind:
				finding.SetVersion(versionDisplay, check.fixedVersion, kinds.VersionBehind, check.notes)
				// Add guidance (ported verbatim from legacy script)
				finding.AddGuidance(
					fmt.Sprintf("update the app to a build on Electron %s or newer (in-app update, else ask the vendor)", check.fixedVersion),
					fmt.Sprintf("Update the app to a release built on Electron %s (or newer) (check for an in-app update;", check.fixedVersion),
					"if none exists yet, ask the vendor). You cannot patch the embedded runtime yourself.",
				)
			case statusNoFix:
				finding.SetVersion(versionDisplay, check.fixedVersion, kinds.VersionNoFix, check.notes)
				// Add guidance
				finding.AddGuidance(
					fmt.Sprintf("update the app to a build on Electron %s or newer (in-app update, else ask the vendor)", check.fixedVersion),
					fmt.Sprintf("Update the app to a release built on Electron %s (or newer) (check for an in-app update;", check.fixedVersion),
					"if none exists yet, ask the vendor). You cannot patch the embedded runtime yourself.",
				)
			case statusOK:
				finding.SetVersion(versionDisplay, check.fixedVersion, kinds.VersionOK, check.notes)
			case statusUnknown:
				// Version check is already VersionNA (from NewFinding)
				// Status will derive to UNKNOWN
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// versionStatus represents the result of checking an Electron version.
type versionStatus string

const (
	statusBehind  versionStatus = "behind"  // Below fixed version
	statusNoFix   versionStatus = "nofix"   // No fix available for this version
	statusOK      versionStatus = "ok"      // At or above fixed version
	statusUnknown versionStatus = "unknown" // Could not parse version
)

// versionCheck holds the result of checking an Electron version.
type versionCheck struct {
	status       versionStatus
	fixedVersion string
	notes        string
}

// checkElectronVersion checks an Electron version against the fixed versions.
// Ports check_electron_version() from the legacy script.
func checkElectronVersion(v string) versionCheck {
	if v == "" {
		return versionCheck{
			status: statusUnknown,
			notes:  "version not found",
		}
	}

	// Extract major version
	parts := strings.Split(v, ".")
	if len(parts) == 0 {
		return versionCheck{
			status: statusUnknown,
			notes:  fmt.Sprintf("could not parse version: %s", v),
		}
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return versionCheck{
			status: statusUnknown,
			notes:  fmt.Sprintf("could not parse major version: %s", parts[0]),
		}
	}

	// Determine fixed version based on major
	var fixedVersion string
	switch major {
	case 42:
		fixedVersion = "42.11.16"
	case 43:
		fixedVersion = "43.8.1"
	case 44:
		fixedVersion = "44.9.1"
	default:
		if major > 44 {
			return versionCheck{
				status: statusOK,
				notes:  "newer than the fixed lines",
			}
		}
		// Major < 42 has no published fix
		return versionCheck{
			status:       statusNoFix,
			fixedVersion: "42.11.16, 43.8.1 or 44.9.1",
			notes:        "fixes only published for 42.11.16, 43.8.1, 44.9.1",
		}
	}

	// Compare version against fixed version
	parsedV := version.Parse(v)
	parsedFixed := version.Parse(fixedVersion)

	if parsedV.GE(parsedFixed) {
		return versionCheck{
			status: statusOK,
			notes:  fmt.Sprintf("at or above fixed version %s", fixedVersion),
		}
	}

	// Below fixed version - note format matches script: "fixed in 44.9.1"
	return versionCheck{
		status:       statusBehind,
		fixedVersion: fixedVersion,
		notes:        fmt.Sprintf("fixed in %s", fixedVersion),
	}
}

// extractAppPath extracts the .app path from a plist path.
// Input: /path/to/App.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist
// Output: /path/to/App.app
func extractAppPath(plistPath string) string {
	// Find the .app directory
	idx := strings.Index(plistPath, ".app/Contents/")
	if idx == -1 {
		return ""
	}
	return plistPath[:idx+4] // Include ".app"
}

// readPlistVersion reads the CFBundleVersion from an Info.plist file.
// Uses PlistBuddy on macOS (as the legacy script does).
func readPlistVersion(plistPath string, env *kinds.Env) (string, error) {
	// In tests, use fake runner
	// In production, use /usr/libexec/PlistBuddy
	result := env.Run.Run(context.Background(), "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleVersion", plistPath)
	if result.Error != nil || result.ExitCode != 0 {
		return "", fmt.Errorf("failed to read plist: %w", result.Error)
	}
	return strings.TrimSpace(result.Stdout), nil
}

// AbsentText implements kinds.Absent.
func (k *Kind) AbsentText(env *kinds.Env) string {
	if env.Host.OS != "darwin" {
		return "(macOS apps only for now - not checked on this platform)"
	}
	return "no Electron apps found"
}
