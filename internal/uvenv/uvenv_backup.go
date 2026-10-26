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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DiskSpaceChecker is a function that checks available disk space.
// It returns the number of bytes available or an error.
type DiskSpaceChecker func(path string) (uint64, error)

// UVPrepareBackups prepares a backup directory for saving installations.
// Ports uv_prepare_backups from the legacy script (lines 2818-2831).
// It creates the backup root if needed with secure permissions and verifies:
//   - The backup root is not a symlink (refuse substituted symlinks)
//   - The backup root is owned by the current user
//   - The backup root has restrictive permissions (no group/other write)
//   - The backup root is on the same device as the source (for rename-based restore)
//   - The disk has enough space (if checkSpace is provided)
//
// Returns an error if any check fails.
func UVPrepareBackups(source, backupRoot string, checkSpace DiskSpaceChecker) error {
	// Refuse if backup root is a symlink (substituted symlink attack)
	if fi, err := os.Lstat(backupRoot); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup root is a symlink: %s", backupRoot)
	}

	// Create backup root if it doesn't exist
	if fi, err := os.Stat(backupRoot); os.IsNotExist(err) {
		// Create with restrictive permissions
		if err := os.MkdirAll(backupRoot, 0700); err != nil {
			return fmt.Errorf("cannot create backup root: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("cannot stat backup root: %w", err)
	} else {
		// Verify ownership
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot get file info for backup root")
		}

		// Check if owned by current user
		if int(stat.Uid) != currentUID() {
			return fmt.Errorf("backup root not owned by current user")
		}

		// Check permissions - no group or other write bits
		mode := fi.Mode().Perm()
		if mode&0022 != 0 {
			return fmt.Errorf("backup root has insecure permissions: %04o", mode)
		}
	}

	// Verify same device (required for rename-based restore)
	sourceDev := UVStorageDevice(source)
	backupDev := UVStorageDevice(backupRoot)

	if sourceDev == -1 {
		return fmt.Errorf("cannot determine device for source: %s", source)
	}
	if backupDev == -1 {
		return fmt.Errorf("cannot determine device for backup root: %s", backupRoot)
	}
	if sourceDev != backupDev {
		return fmt.Errorf("backup root is on a different device (source: %d, backup: %d)", sourceDev, backupDev)
	}

	// Check disk space if a checker was provided
	if checkSpace != nil {
		if _, err := checkSpace(backupRoot); err != nil {
			return fmt.Errorf("disk space check failed: %w", err)
		}
	}

	return nil
}

// UVSavePythonInstalls saves Python installations for a specific minor version.
// Ports uv_save_python_installs from the legacy script (lines 2833-2842).
// It copies all cpython-{minor}.* directories from pythonDir to backup.
// Returns an error if any of the installations are symlinks (refuse to backup symlinks).
//
// Parameters:
//   - pythonDir: the UV_PYTHON_INSTALL_DIR
//   - minor: the minor version (e.g., "3.12")
//   - backup: the backup directory
//
// Returns an error if the save fails.
func UVSavePythonInstalls(pythonDir, minor, backup string) error {
	// Create backup directory
	if err := os.MkdirAll(backup, 0700); err != nil {
		return fmt.Errorf("cannot create backup directory: %w", err)
	}

	// Open the Python directory
	d, err := os.Open(pythonDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No Python directory, nothing to save
		}
		return fmt.Errorf("cannot open Python directory: %w", err)
	}
	defer func() { _ = d.Close() }()

	// Read all entries
	entries, err := d.Readdir(-1)
	if err != nil {
		return fmt.Errorf("cannot read Python directory: %w", err)
	}

	// Find matching installations
	prefix := fmt.Sprintf("cpython-%s.", minor)
	for _, entry := range entries {
		name := entry.Name()

		// Check if it matches the pattern cpython-{minor}.*
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		path := filepath.Join(pythonDir, name)

		// Refuse if it's a symlink
		if entry.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to backup symlink: %s", path)
		}

		// Skip if not a directory
		if !entry.IsDir() {
			continue
		}

		// Copy the directory
		backupPath := filepath.Join(backup, name)
		if err := CopyTree(path, backupPath); err != nil {
			return fmt.Errorf("cannot copy installation %s: %w", name, err)
		}
	}

	return nil
}

// UVRestorePythonInstalls restores Python installations from backup.
// Ports uv_restore_python_installs from the legacy script (lines 2843-2857).
// It moves saved installations back to the Python directory.
// If an installation already exists, it moves it to failed-installations.
//
// Parameters:
//   - pythonDir: the UV_PYTHON_INSTALL_DIR
//   - backup: the backup directory containing saved installations
//
// Returns an error if the restore fails.
func UVRestorePythonInstalls(pythonDir, backup string) error {
	// Create failed-installations directory
	failedDir := filepath.Join(backup, "failed-installations")
	if err := os.MkdirAll(failedDir, 0700); err != nil {
		return fmt.Errorf("cannot create failed-installations directory: %w", err)
	}

	// Create python directory if it doesn't exist
	if err := os.MkdirAll(pythonDir, 0755); err != nil {
		return fmt.Errorf("cannot create Python directory: %w", err)
	}

	// Open the backup installations directory
	installationsDir := filepath.Join(backup, "installations")
	d, err := os.Open(installationsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No backup, nothing to restore
		}
		return fmt.Errorf("cannot open backup installations: %w", err)
	}
	defer func() { _ = d.Close() }()

	// Read all entries
	entries, err := d.Readdir(-1)
	if err != nil {
		return fmt.Errorf("cannot read backup installations: %w", err)
	}

	// Restore each installation
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			continue
		}

		backupPath := filepath.Join(installationsDir, name)
		currentPath := filepath.Join(pythonDir, name)

		// If an installation already exists, move it to failed-installations
		if fi, err := os.Lstat(currentPath); err == nil {
			// It exists (file or symlink)
			failedPath := filepath.Join(failedDir, name)
			if err := os.Rename(currentPath, failedPath); err != nil {
				return fmt.Errorf("cannot move failed installation %s: %w", name, err)
			}
			_ = fi // Use fi to avoid unused variable warning
		}

		// Move the saved original back without allocating another full installation
		if err := os.Rename(backupPath, currentPath); err != nil {
			return fmt.Errorf("cannot restore installation %s: %w", name, err)
		}
	}

	return nil
}

// UVRestoreTool restores a tool environment from backup.
// Ports uv_restore_tool from the legacy script (lines 2916-2923).
// It moves the failed environment to backup/failed-environment and restores
// the saved environment from backup/environment.
//
// Parameters:
//   - dir: the tool directory
//   - bindir: the bin directory for the tool
//   - backup: the backup directory
//
// Returns an error if the restore fails.
func UVRestoreTool(dir, bindir, backup string) error {
	// Create parent directory if needed
	parentDir := filepath.Dir(dir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("cannot create parent directory: %w", err)
	}

	// Preserve the failed environment rather than deleting
	if _, err := os.Stat(dir); err == nil {
		failedPath := filepath.Join(backup, "failed-environment")
		if err := os.Rename(dir, failedPath); err != nil {
			return fmt.Errorf("cannot move failed environment: %w", err)
		}
	}

	// Move the saved original back
	savedPath := filepath.Join(backup, "environment")
	if err := os.Rename(savedPath, dir); err != nil {
		return fmt.Errorf("cannot restore environment: %w", err)
	}

	// Restore bin links
	return UVRestoreLinks(bindir, filepath.Join(backup, "bin-links"), string(LinkKindTool), dir, "")
}

// UVToolEntrypointsSafe verifies that all entrypoints for a tool are safe to restore.
// Ports uv_tool_entrypoints_safe from the legacy script (lines 2929-2960).
// It checks that:
//   - All entrypoints listed by `uv tool list --show-paths` are in the expected bindir
//   - Any existing entrypoints are symlinks that point to the tool directory
//
// The caller runs `uv tool list --show-paths` and passes its output as listing.
//
// Parameters:
//   - name: the tool name
//   - dir: the tool directory
//   - bindir: the expected bin directory
//   - listing: the output of `uv tool list --show-paths`
//
// Returns true if all entrypoints are safe, false otherwise.
func UVToolEntrypointsSafe(name, dir, bindir, listing string) (bool, error) {
	// Parse the listing
	// Format:
	//   alpha v1.0 (/path/to/tools/alpha)
	//   - alpha-cli (/path/to/bin/alpha-cli)
	//   - .alpha-cli (/path/to/bin/.alpha-cli)
	//
	// We need to find the tool entry and verify all its entrypoints

	lines := strings.Split(listing, "\n")
	active := false
	found := false

	for _, line := range lines {
		// Check for tool entry
		if strings.HasPrefix(line, name+" ") {
			active = true
			found = true
			continue
		}

		// Check for entrypoint
		if strings.HasPrefix(line, "- ") {
			if !active {
				continue
			}

			// Extract path from line like "- alpha-cli (/path/to/bin/alpha-cli)"
			// or "- .alpha-cli (/path/to/bin/.alpha-cli)"
			entrypointLine := strings.TrimSpace(line[2:]) // Remove "- "

			// Find the path in parentheses
			start := strings.LastIndex(entrypointLine, "(")
			end := strings.LastIndex(entrypointLine, ")")
			if start == -1 || end == -1 || end <= start {
				return false, fmt.Errorf("malformed entrypoint line: %s", line)
			}

			path := entrypointLine[start+1 : end]

			// Verify path is absolute
			if !filepath.IsAbs(path) {
				return false, fmt.Errorf("non-absolute entrypoint path: %s", path)
			}

			// Verify parent directory is bindir
			parent := filepath.Dir(path)

			// Don't resolve symlinks on parent - compare the paths directly
			// The script uses `cd -P` which resolves, but the bindir variable is also resolved
			// So we need to resolve both to match
			// The script resolves the parent with `cd -P ... || return 1`: a parent
			// that cannot be resolved is unsafe, not "compare the paths as given".
			resolvedParent, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return false, fmt.Errorf("cannot resolve the directory of entrypoint %s: %w", path, err)
			}
			// bindir is physical in the script; resolve ours the same way.
			resolvedBindir, err := filepath.EvalSymlinks(bindir)
			if err != nil {
				resolvedBindir = bindir
			}
			if resolvedParent != resolvedBindir {
				return false, fmt.Errorf("entrypoint %s not in expected bindir %s", path, bindir)
			}

			// If entrypoint exists, verify it's a symlink pointing to the tool directory
			if fi, err := os.Lstat(path); err == nil {
				// Path exists - must be a symlink
				if fi.Mode()&os.ModeSymlink == 0 {
					return false, fmt.Errorf("entrypoint %s exists but is not a symlink", path)
				}
				// And it must match the tool directory
				matches, err := UVLinkMatches(path, string(LinkKindTool), dir, "")
				if err != nil || !matches {
					return false, fmt.Errorf("entrypoint %s does not belong to tool", path)
				}
			}

			continue
		}

		// Empty lines are OK
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Any other line deactivates the tool
		active = false
	}

	// Must have found the tool
	if !found {
		return false, fmt.Errorf("tool %s not found in listing", name)
	}

	return true, nil
}

// CopyTree copies a directory tree like `cp -pR`: symlinks are copied as symlinks (never
// followed), and file and directory modes and modification times are preserved. A directory's
// own mode is applied after its contents are copied, so a read-only directory can be copied.
func CopyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dstPath); err != nil {
				return err
			}
		case entry.IsDir():
			if err := CopyTree(srcPath, dstPath); err != nil {
				return err
			}
		default:
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	if err := os.Chmod(dst, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, fi.ModTime(), fi.ModTime())
}

// copyFile copies a regular file, preserving its mode and modification time.
func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	fi, err := s.Stat()
	if err != nil {
		return err
	}
	d, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		_ = d.Close()
		return err
	}
	if err := d.Close(); err != nil {
		return err
	}
	if err := os.Chmod(dst, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, fi.ModTime(), fi.ModTime())
}

// currentUID is the effective user the backup root must belong to. It is a
// variable so a test can stand in for a root owned by someone else, which a
// non-root test cannot create on disk.
var currentUID = os.Getuid
