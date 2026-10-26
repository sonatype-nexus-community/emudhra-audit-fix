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

package uvenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ManagedMinor extracts the minor version from a managed Python directory name.
// Directory names are like "cpython-3.12.0-macos-aarch64-none".
// Returns "3.12" for Python 3.12.x, or empty string if not a managed install.
// Ports uv_managed_minor (lines 701-710).
//
// Like the script, only an install under uv's Python directory counts (a cpython-named
// directory anywhere else is not uv's to upgrade), and an unknown Python directory
// means nothing is managed.
func (e *Env) ManagedMinor(dirPath, fullVersion string, impl string) string {
	if impl != "cpython" || e.PythonDir == "" {
		return ""
	}
	// dirPath is normally physical while the configured directory may go through a symlink
	// (macOS /var), so accept either spelling of the directory.
	under := func(root string) bool {
		return strings.HasPrefix(dirPath, root+string(filepath.Separator)+"cpython-")
	}
	ok := under(e.PythonDir)
	if real, err := filepath.EvalSymlinks(e.PythonDir); err == nil && !ok {
		ok = under(real)
	}
	if !ok {
		return ""
	}

	// Extract directory name
	dirName := filepath.Base(dirPath)

	// Must start with "cpython-"
	if !strings.HasPrefix(dirName, "cpython-") {
		return ""
	}

	// Must match the expected version prefix
	expectedPrefix := "cpython-" + fullVersion + "-"
	if !strings.HasPrefix(dirName, expectedPrefix) {
		return ""
	}

	// Must not have + (free-threaded, debug variants)
	if strings.Contains(dirName, "+") {
		return ""
	}

	// Extract minor version from fullVersion (e.g., "3.12.0" -> "3.12")
	parts := strings.Split(fullVersion, ".")
	if len(parts) < 2 {
		return ""
	}

	minor := parts[0] + "." + parts[1]

	// Validate minor version format: 3.X or 3.XX
	matched, _ := regexp.MatchString(`^3\.\d{1,2}$`, minor)
	if !matched {
		return ""
	}

	return minor
}

// PythonLatest queries uv's bundled catalogue offline for the latest available
// Python version for a given minor version. It runs
// "uv python list --only-downloads --managed-python cpython@MINOR" and parses
// the output to find the newest patch version.
// Ports uv_python_latest (lines 712-731).
func (e *Env) PythonLatest(ctx context.Context, dirPath, fullVersion string) (string, error) {
	// Extract minor version
	minor := e.ManagedMinor(dirPath, fullVersion, "cpython")
	if minor == "" {
		return "", fmt.Errorf("not a managed cpython install")
	}

	// Extract suffix from directory name (e.g., "-macos-aarch64-none")
	dirName := filepath.Base(dirPath)
	suffix := ""
	if idx := strings.Index(dirName, "cpython-"+fullVersion); idx >= 0 {
		suffix = dirName[idx+len("cpython-"+fullVersion):]
	}

	// Run uv python list
	output, err := e.Read(ctx, "python", "list", "--only-downloads", "--managed-python", "cpython@"+minor)
	if err != nil {
		return "unknown", nil
	}

	// Parse output to find the latest version with matching suffix
	// Format: "cpython-3.12.0-macos-aarch64-none <download available>"
	var latest string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse "cpython-VERSION-SUFFIX <download available>"
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		key := parts[0]
		if !strings.HasPrefix(key, "cpython-") {
			continue
		}

		// Check if suffix matches
		if suffix != "" && !strings.HasSuffix(key, suffix) {
			continue
		}

		// Extract version from "cpython-VERSION-SUFFIX"
		versionPart := strings.TrimPrefix(key, "cpython-")
		if suffix != "" {
			versionPart = strings.TrimSuffix(versionPart, suffix)
		}

		// Validate version format
		if !isValidVersion(versionPart) {
			continue
		}

		// Check that version matches the minor
		if !strings.HasPrefix(versionPart, minor+".") && versionPart != minor {
			continue
		}

		// Update latest if this is newer
		if latest == "" || compareVersions(versionPart, latest) > 0 {
			latest = versionPart
		}
	}

	// A listing that was read but holds nothing for this family is "" (the audit then says uv
	// reports no downloadable patch); only a FAILED listing is "unknown", returned above.

	return latest, nil
}

// PythonNewestInstalled finds the newest installed Python version for a given minor.
// It scans the PythonDir for cpython-MINOR.* directories and returns the newest patch.
// Ports uv_python_newest_installed (lines 733-747).
func (e *Env) PythonNewestInstalled(ctx context.Context, dirPath, fullVersion string) (string, error) {
	// Extract minor version and suffix
	minor := e.ManagedMinor(dirPath, fullVersion, "cpython")
	if minor == "" {
		return fullVersion, nil // Not managed, return the provided version
	}

	// Extract suffix from directory name
	dirName := filepath.Base(dirPath)
	suffix := ""
	if idx := strings.Index(dirName, "cpython-"+fullVersion); idx >= 0 {
		suffix = dirName[idx+len("cpython-"+fullVersion):]
	}

	// Scan PythonDir for matching versions
	pattern := filepath.Join(e.PythonDir, "cpython-"+minor+".*"+suffix)
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fullVersion, nil // fallback to provided version
	}

	// Find the newest version
	newest := fullVersion
	for _, match := range matches {
		// Check for python3 executable
		pythonPath := filepath.Join(match, "bin", "python3")
		if _, err := os.Stat(pythonPath); os.IsNotExist(err) {
			continue
		}

		// Extract version from directory name
		matchName := filepath.Base(match)
		versionPart := strings.TrimPrefix(matchName, "cpython-")
		if suffix != "" {
			versionPart = strings.TrimSuffix(versionPart, suffix)
		}

		// Validate version
		if !isValidVersion(versionPart) {
			continue
		}

		// Check minor match
		if !strings.HasPrefix(versionPart, minor+".") && versionPart != minor {
			continue
		}

		// Update newest if this is newer
		if compareVersions(versionPart, newest) > 0 {
			newest = versionPart
		}
	}

	return newest, nil
}

// PythonIsSelected checks if a Python version is selected via UV_PYTHON or symlinks.
// It checks if the installation is the preferred runtime for its minor version.
// Ports uv_python_is_selected (lines 749-817).
func (e *Env) PythonIsSelected(ctx context.Context, dirPath, fullVersion string) bool {
	// Extract minor version and suffix
	minor := e.ManagedMinor(dirPath, fullVersion, "cpython")
	if minor == "" {
		return false
	}

	// Extract suffix
	dirName := filepath.Base(dirPath)
	suffix := ""
	if idx := strings.Index(dirName, "cpython-"+fullVersion); idx >= 0 {
		suffix = dirName[idx+len("cpython-"+fullVersion):]
	}

	// Check if the preferred directory exists and matches this installation
	preferred := filepath.Join(e.PythonDir, "cpython-"+minor+suffix)
	if info, err := os.Stat(preferred); err == nil && info.IsDir() {
		// Resolve preferred to check if it's the same as dirPath
		if resolved, err := filepath.EvalSymlinks(preferred); err == nil {
			if resolvedDir, err := filepath.EvalSymlinks(dirPath); err == nil {
				if resolved == resolvedDir {
					return true
				}
			}
		}
	}

	// uv_python_is_selected: the launchers are in uv's python bin directory, which uv reports.
	// If it cannot be found the script cannot rule the install out, so it is conservative and
	// answers "selected" (`bindir=$(uv_bin_dir python) || return 0`).
	binDir, err := e.BinDir(ctx, "python")
	if err != nil {
		return true
	}

	// Check common executable names
	executables := []string{"python", "python3", "python" + minor}
	for _, exe := range executables {
		exePath := filepath.Join(binDir, exe)
		info, err := os.Lstat(exePath)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		dest, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(binDir, dest)
		}
		resolved, err := filepath.EvalSymlinks(dest)
		if err != nil {
			continue
		}
		// compare physical paths (macOS /var vs /private/var)
		if resolvedDir, err := filepath.EvalSymlinks(dirPath); err == nil &&
			strings.HasPrefix(resolved, resolvedDir+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// isValidVersion checks if a string is a valid version number (digits and dots only).
func isValidVersion(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// compareVersions compares two semantic versions and returns:
// -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")

	// Pad to equal length
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			if _, err := fmt.Sscanf(p1[i], "%d", &n1); err != nil {
				continue // skip malformed
			}
		}
		if i < len(p2) {
			if _, err := fmt.Sscanf(p2[i], "%d", &n2); err != nil {
				continue // skip malformed
			}
		}

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}

// PythonImports returns the list of Python installation directories.
// For use by uvpython Kind - reads from PythonDir.
func (e *Env) PythonImports(ctx context.Context) ([]string, error) {
	if e.PythonDir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(e.PythonDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "cpython-") {
			dirs = append(dirs, filepath.Join(e.PythonDir, entry.Name()))
		}
	}

	sort.Strings(dirs)
	return dirs, nil
}
