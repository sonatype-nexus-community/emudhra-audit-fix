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
	"os"
	"path/filepath"
	"strings"
)

// LinkKind identifies the type of symlink for matching purposes.
type LinkKind string

const (
	LinkKindTool   LinkKind = "tool"   // Tool entrypoint symlink
	LinkKindPython LinkKind = "python" // Python installation symlink
)

// UVLinkMatches checks if a symlink points to a target directory.
// Ports uv_link_matches from the legacy script (lines 2762-2777).
// For tool links, it checks both the direct target and the resolved target.
// For python links, it checks if the resolved target matches the minor version pattern.
//
// Parameters:
//   - linkPath: path to the symlink
//   - kind: "tool" or "python"
//   - target: the directory to match against (tool dir or minor version)
//
// Returns true if the symlink matches, false otherwise.
func UVLinkMatches(linkPath, kind, target, pythonDir string) (bool, error) {
	// Resolve the symlink fully. A dangling link (its target was removed or not
	// yet created, which is exactly what a failed upgrade leaves behind) cannot
	// be resolved; like the script's resolve(), fall back to the path itself
	// rather than giving up, so the link is still judged by its direct target.
	dest, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		dest = linkPath
	}

	// Compare resolved paths with resolved paths. The script's directories come
	// from `cd -P ... && pwd`, which are already physical; here the tool
	// directory may be given through a symlink (on macOS /var is /private/var),
	// so resolve it the same way the link was resolved or no prefix would match.
	if kind == string(LinkKindTool) {
		if real, rerr := filepath.EvalSymlinks(target); rerr == nil {
			target = real
		}
	}

	switch LinkKind(kind) {
	case LinkKindTool:
		// For tool links, check both the immediate target and the resolved target
		// The entry point itself may be a symlink to the shared Python binary.
		// Ownership follows its immediate target in the tool environment as well.

		// Read the immediate symlink target (not resolved)
		direct, err := os.Readlink(linkPath)
		if err != nil {
			return false, err
		}

		// Make it absolute if it's relative
		if !filepath.IsAbs(direct) {
			direct = filepath.Join(filepath.Dir(linkPath), direct)
		}

		// Get the parent directory of the direct target
		directParent := filepath.Dir(direct)
		parent, err := filepath.EvalSymlinks(directParent)
		if err != nil {
			// If we can't resolve, try to continue with just the resolved dest
			parent = directParent
		}

		// Check if direct target is under the tool directory
		directPath := filepath.Join(parent, filepath.Base(direct))
		if strings.HasPrefix(directPath, target+string(filepath.Separator)) {
			return true, nil
		}

		// Check if resolved destination is under the tool directory
		if strings.HasPrefix(dest, target+string(filepath.Separator)) {
			return true, nil
		}

		return false, nil

	case LinkKindPython:
		// Like the script's `case $dest in "$UV_PYTHON_DIR"/cpython-"$3".*|...-*`: the resolved
		// destination lies under the Python directory in a cpython-MINOR.* or cpython-MINOR-*
		// entry. A shell pattern's * spans "/", so a launcher that resolves to
		// cpython-3.12.4-.../bin/python3.12 matches, and one in another install does not.
		if pythonDir == "" {
			return false, nil
		}
		if real, rerr := filepath.EvalSymlinks(pythonDir); rerr == nil {
			pythonDir = real // dest is physical; so must the directory it is compared with be
		}
		root := filepath.Join(pythonDir, "cpython-"+target)
		if strings.HasPrefix(dest, root+".") || strings.HasPrefix(dest, root+"-") {
			return true, nil
		}
		return false, nil

	default:
		return false, fmt.Errorf("unknown link kind: %s", kind)
	}
}

// UVSaveLinks saves matching symlinks from a directory to a backup directory.
// Ports uv_save_links from the legacy script (lines 2779-2787).
// It finds all symlinks in dir that match the given kind/target and copies them
// (as symlinks, preserving the link target) to the backup directory.
//
// Parameters:
//   - dir: directory to scan for symlinks
//   - backup: backup directory to save symlinks to (will be created if needed)
//   - kind: "tool" or "python"
//   - target: the target to match against
//   - pythonDir: uv's Python directory (python links only; "" for tool links)
//
// Returns an error if the backup directory cannot be created or if copying fails.
func UVSaveLinks(dir, backup, kind, target, pythonDir string) error {
	// Create backup directory
	if err := os.MkdirAll(backup, 0700); err != nil {
		return fmt.Errorf("cannot create backup directory: %w", err)
	}

	// Open the directory
	d, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No directory to save from
		}
		return fmt.Errorf("cannot open directory: %w", err)
	}
	defer func() { _ = d.Close() }()

	// Read all entries (including hidden files, like the shell glob patterns)
	entries, err := d.Readdir(-1)
	if err != nil {
		return fmt.Errorf("cannot read directory: %w", err)
	}

	// Process each entry
	for _, entry := range entries {
		name := entry.Name()

		// Skip . and ..
		if name == "." || name == ".." {
			continue
		}

		path := filepath.Join(dir, name)

		// Check if it's a symlink
		if entry.Mode()&os.ModeSymlink == 0 {
			continue
		}

		// Check if it matches the target
		matches, err := UVLinkMatches(path, kind, target, pythonDir)
		if err != nil {
			// Log error but continue
			continue
		}
		if !matches {
			continue
		}

		// Copy the symlink (preserving the link target)
		// Read the link target
		linkTarget, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("cannot read symlink %s: %w", path, err)
		}

		// Create the symlink in the backup directory
		backupPath := filepath.Join(backup, name)

		// Remove existing backup if present
		_ = os.Remove(backupPath)

		// Create the symlink
		if err := os.Symlink(linkTarget, backupPath); err != nil {
			return fmt.Errorf("cannot create symlink %s: %w", backupPath, err)
		}
	}

	return nil
}

// UVRestoreLinks restores symlinks from a backup directory to the original directory.
// Ports uv_restore_links from the legacy script (lines 2789-2802).
// It removes matching symlinks from dir and restores the ones from backup.
// Returns an error if the restore fails or if a file already exists in dir.
//
// Parameters:
//   - dir: directory to restore symlinks to
//   - backup: backup directory containing saved symlinks
//   - kind: "tool" or "python"
//   - target: the target to match against
//   - pythonDir: uv's Python directory (python links only; "" for tool links)
//
// Returns an error if the restore fails.
func UVRestoreLinks(dir, backup, kind, target, pythonDir string) error {
	// First pass: remove matching symlinks from the directory
	d, err := os.Open(dir)
	if err == nil {
		entries, err := d.Readdir(-1)
		_ = d.Close()
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if name == "." || name == ".." {
					continue
				}

				path := filepath.Join(dir, name)

				// Check if it's a symlink
				if entry.Mode()&os.ModeSymlink == 0 {
					continue
				}

				// Check if it matches the target
				matches, err := UVLinkMatches(path, kind, target, pythonDir)
				if err != nil {
					continue
				}
				if !matches {
					continue
				}

				// Remove it
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("cannot remove symlink %s: %w", path, err)
				}
			}
		}
	}

	// Second pass: restore symlinks from backup
	bd, err := os.Open(backup)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No backup, nothing to restore
		}
		return fmt.Errorf("cannot open backup directory: %w", err)
	}

	backupEntries, err := bd.Readdir(-1)
	_ = bd.Close()
	if err != nil {
		return fmt.Errorf("cannot read backup directory: %w", err)
	}

	for _, entry := range backupEntries {
		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}

		backupPath := filepath.Join(backup, name)

		// Check if it's a symlink
		if entry.Mode()&os.ModeSymlink == 0 {
			continue
		}

		// Check if a file or link already exists in the target directory
		// Do not overwrite a file or link claimed by another tool
		targetPath := filepath.Join(dir, name)
		if _, err := os.Lstat(targetPath); err == nil {
			// File or link exists - refuse to overwrite
			return fmt.Errorf("refusing to overwrite existing file %s", targetPath)
		}

		// Move the symlink from backup to the target directory
		// Note: We use rename (mv) not copy, as in the script
		if err := os.Rename(backupPath, targetPath); err != nil {
			return fmt.Errorf("cannot restore symlink %s: %w", targetPath, err)
		}
	}

	return nil
}
