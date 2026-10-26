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

package uvenv_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvenv"
)

func TestUVLinkMatches(t *testing.T) {
	t.Run("tool link matches when target is under tool directory", func(t *testing.T) {
		// Create a temp directory structure
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		toolBinDir := filepath.Join(toolDir, "bin")
		binDir := filepath.Join(tmpDir, "bin")
		if err := os.MkdirAll(toolBinDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a symlink to a file in the tool directory
		targetFile := filepath.Join(toolBinDir, "python")
		if err := os.WriteFile(targetFile, []byte("#!/bin/sh\necho python"), 0755); err != nil {
			t.Fatal(err)
		}

		linkPath := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(targetFile, linkPath); err != nil {
			t.Fatal(err)
		}

		// Check that it matches
		matches, err := uvenv.UVLinkMatches(linkPath, string(uvenv.LinkKindTool), toolDir, "")
		if err != nil {
			t.Fatalf("UVLinkMatches failed: %v", err)
		}
		if !matches {
			t.Error("Expected link to match tool directory")
		}
	})

	t.Run("tool link does not match when target is outside tool directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		otherDir := filepath.Join(tmpDir, "tools", "beta")
		binDir := filepath.Join(tmpDir, "bin")
		if err := os.MkdirAll(toolDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(otherDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a symlink to a file in a different tool directory
		targetFile := filepath.Join(otherDir, "bin", "python")
		if err := os.MkdirAll(filepath.Join(otherDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetFile, []byte("#!/bin/sh\necho python"), 0755); err != nil {
			t.Fatal(err)
		}

		linkPath := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(targetFile, linkPath); err != nil {
			t.Fatal(err)
		}

		// Check that it does not match
		matches, err := uvenv.UVLinkMatches(linkPath, string(uvenv.LinkKindTool), toolDir, "")
		if err != nil {
			t.Fatalf("UVLinkMatches failed: %v", err)
		}
		if matches {
			t.Error("Expected link not to match tool directory")
		}
	})

	t.Run("python link matches minor version", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		if err := os.MkdirAll(pythonDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a Python installation directory
		installDir := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none")
		if err := os.MkdirAll(installDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a symlink to the Python installation
		linkPath := filepath.Join(tmpDir, "python3.12")
		if err := os.Symlink(installDir, linkPath); err != nil {
			t.Fatal(err)
		}

		// Check that it matches 3.12
		matches, err := uvenv.UVLinkMatches(linkPath, string(uvenv.LinkKindPython), "3.12", pythonDir)
		if err != nil {
			t.Fatalf("UVLinkMatches failed: %v", err)
		}
		if !matches {
			t.Error("Expected link to match Python 3.12")
		}

		// Check that it does not match 3.13
		matches, err = uvenv.UVLinkMatches(linkPath, string(uvenv.LinkKindPython), "3.13", pythonDir)
		if err != nil {
			t.Fatalf("UVLinkMatches failed: %v", err)
		}
		if matches {
			t.Error("Expected link not to match Python 3.13")
		}
	})
}

func TestUVSaveLinksAndRestoreLinks(t *testing.T) {
	t.Run("round trip saves and restores symlinks", func(t *testing.T) {
		// Create a temp directory structure
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")
		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create files in the tool directory
		pythonFile := filepath.Join(toolDir, "bin", "python")
		if err := os.WriteFile(pythonFile, []byte("#!/bin/sh\necho python"), 0755); err != nil {
			t.Fatal(err)
		}

		cliFile := filepath.Join(toolDir, "bin", "alpha-cli")
		if err := os.WriteFile(cliFile, []byte("#!/bin/sh\necho alpha-cli"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlinks in bin dir
		link1 := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(cliFile, link1); err != nil {
			t.Fatal(err)
		}

		link2 := filepath.Join(binDir, ".alpha-cli")
		if err := os.Symlink(cliFile, link2); err != nil {
			t.Fatal(err)
		}

		// Create an unrelated symlink (should not be saved)
		unrelatedFile := filepath.Join(tmpDir, "other")
		if err := os.WriteFile(unrelatedFile, []byte("unrelated"), 0644); err != nil {
			t.Fatal(err)
		}
		link3 := filepath.Join(binDir, "unrelated")
		if err := os.Symlink(unrelatedFile, link3); err != nil {
			t.Fatal(err)
		}

		// Save links
		if err := uvenv.UVSaveLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVSaveLinks failed: %v", err)
		}

		// Verify backup directory contains only matching symlinks
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Errorf("Expected 2 backed up symlinks, got %d", len(entries))
		}

		// Verify backup symlinks point to the right targets
		for _, entry := range entries {
			backupPath := filepath.Join(backupDir, entry.Name())
			target, err := os.Readlink(backupPath)
			if err != nil {
				t.Fatal(err)
			}
			if target != cliFile {
				t.Errorf("Expected backup symlink to point to %s, got %s", cliFile, target)
			}
		}

		// Remove the original symlinks
		if err := os.Remove(link1); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(link2); err != nil {
			t.Fatal(err)
		}

		// Restore links
		if err := uvenv.UVRestoreLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVRestoreLinks failed: %v", err)
		}

		// Verify the symlinks are restored
		target1, err := os.Readlink(filepath.Join(binDir, "alpha-cli"))
		if err != nil {
			t.Fatal(err)
		}
		if target1 != cliFile {
			t.Errorf("Expected restored symlink to point to %s, got %s", cliFile, target1)
		}

		target2, err := os.Readlink(filepath.Join(binDir, ".alpha-cli"))
		if err != nil {
			t.Fatal(err)
		}
		if target2 != cliFile {
			t.Errorf("Expected restored symlink to point to %s, got %s", cliFile, target2)
		}

		// Unrelated symlink should still exist
		if _, err := os.Lstat(link3); err != nil {
			t.Error("Expected unrelated symlink to still exist")
		}
	})

	t.Run("restore after live directory was modified", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")
		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create original file
		originalFile := filepath.Join(toolDir, "bin", "alpha-cli")
		if err := os.WriteFile(originalFile, []byte("original"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlink
		linkPath := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(originalFile, linkPath); err != nil {
			t.Fatal(err)
		}

		// Save links
		if err := uvenv.UVSaveLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVSaveLinks failed: %v", err)
		}

		// Modify the file
		if err := os.WriteFile(originalFile, []byte("modified"), 0755); err != nil {
			t.Fatal(err)
		}

		// Add a new symlink that wasn't in the backup (pointing elsewhere, not toolDir)
		otherFile := filepath.Join(filepath.Dir(toolDir), "other")
		if err := os.WriteFile(otherFile, []byte("other"), 0755); err != nil {
			t.Fatal(err)
		}
		newLink := filepath.Join(binDir, "new-cli")
		if err := os.Symlink(otherFile, newLink); err != nil {
			t.Fatal(err)
		}

		// Remove the original symlink
		if err := os.Remove(linkPath); err != nil {
			t.Fatal(err)
		}

		// Restore links
		if err := uvenv.UVRestoreLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVRestoreLinks failed: %v", err)
		}

		// Verify the original symlink is restored
		target, err := os.Readlink(linkPath)
		if err != nil {
			t.Fatal(err)
		}
		if target != originalFile {
			t.Errorf("Expected restored symlink to point to %s, got %s", originalFile, target)
		}

		// Verify the modification is preserved (file content should be "modified")
		content, err := os.ReadFile(originalFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "modified" {
			t.Errorf("Expected file content to be 'modified', got %s", string(content))
		}

		// The new symlink should still exist (it doesn't point to toolDir)
		if _, err := os.Lstat(newLink); err != nil {
			t.Error("Expected new symlink to still exist")
		}
	})

	t.Run("restore refuses to overwrite existing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")
		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create original file and symlink
		originalFile := filepath.Join(toolDir, "bin", "alpha-cli")
		if err := os.WriteFile(originalFile, []byte("original"), 0755); err != nil {
			t.Fatal(err)
		}

		linkPath := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(originalFile, linkPath); err != nil {
			t.Fatal(err)
		}

		// Save links
		if err := uvenv.UVSaveLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVSaveLinks failed: %v", err)
		}

		// Create a different file with the same name
		otherFile := filepath.Join(tmpDir, "other")
		if err := os.WriteFile(otherFile, []byte("other"), 0755); err != nil {
			t.Fatal(err)
		}

		// Replace the symlink with one pointing elsewhere
		if err := os.Remove(linkPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(otherFile, linkPath); err != nil {
			t.Fatal(err)
		}

		// Try to restore - should fail because the symlink points elsewhere
		err := uvenv.UVRestoreLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, "")
		if err == nil {
			t.Fatal("Expected error when trying to restore over existing file")
		}
	})

	t.Run("restore removes new links added during upgrade", func(t *testing.T) {
		// This test kills mutation: "restore without removing the matching links first"
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")
		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create original file and link
		cliFile := filepath.Join(toolDir, "bin", "alpha-cli")
		if err := os.WriteFile(cliFile, []byte("original"), 0755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(binDir, "alpha-cli")
		if err := os.Symlink(cliFile, link); err != nil {
			t.Fatal(err)
		}

		// Save the link
		if err := uvenv.UVSaveLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVSaveLinks failed: %v", err)
		}

		// During upgrade, a new entrypoint was added that points to the tool
		newFile := filepath.Join(toolDir, "bin", "new-entrypoint")
		if err := os.WriteFile(newFile, []byte("new"), 0755); err != nil {
			t.Fatal(err)
		}
		newLink := filepath.Join(binDir, "new-entrypoint")
		if err := os.Symlink(newFile, newLink); err != nil {
			t.Fatal(err)
		}

		// Remove the original link (simulating upgrade removed it)
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}

		// Restore
		if err := uvenv.UVRestoreLinks(binDir, backupDir, string(uvenv.LinkKindTool), toolDir, ""); err != nil {
			t.Fatalf("UVRestoreLinks failed: %v", err)
		}

		// Original link should be restored
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatal(err)
		}
		if target != cliFile {
			t.Errorf("Expected restored link to point to %s, got %s", cliFile, target)
		}

		// The new link should NOT exist (it should have been removed during restore)
		if _, err := os.Lstat(newLink); err == nil {
			t.Error("Expected new-entrypoint to be removed during restore, but it still exists")
		}
	})
}

// uv's launchers (~/.local/bin/python3.12) resolve to the interpreter INSIDE an install, not to the
// install directory; the script's shell pattern matches those because * spans "/".
func TestUVLinkMatchesPythonLaunchersThatResolveInsideAnInstall(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pythonDir := filepath.Join(root, "python")
	for _, d := range []string{"cpython-3.12.4-macos-aarch64-none", "cpython-3.13.1-macos-aarch64-none", "cpython-3.11-macos-aarch64-none", "elsewhere"} {
		if err := os.MkdirAll(filepath.Join(pythonDir, d, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pythonDir, d, "bin", "python"), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, d string) string {
		p := filepath.Join(root, name)
		if err := os.Symlink(filepath.Join(pythonDir, d, "bin", "python"), p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, dir, minor string
		want             bool
	}{
		{"launcher in the minor line", "cpython-3.12.4-macos-aarch64-none", "3.12", true},
		{"launcher in another minor line", "cpython-3.13.1-macos-aarch64-none", "3.12", false},
		{"launcher in a minor-named directory", "cpython-3.11-macos-aarch64-none", "3.11", true},
		{"launcher outside any cpython install", "elsewhere", "3.12", false},
	}
	for _, c := range cases {
		got, err := uvenv.UVLinkMatches(link(strings.ReplaceAll(c.name, " ", "-"), c.dir), string(uvenv.LinkKindPython), c.minor, pythonDir)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
	if got, _ := uvenv.UVLinkMatches(link("nodir", "cpython-3.12.4-macos-aarch64-none"), string(uvenv.LinkKindPython), "3.12", ""); got {
		t.Error("without a Python directory nothing can be judged a uv Python link")
	}
	// 3.1 must not match 3.12 (the pattern is cpython-3.1.* | cpython-3.1-*).
	if got, _ := uvenv.UVLinkMatches(link("prefix", "cpython-3.12.4-macos-aarch64-none"), string(uvenv.LinkKindPython), "3.1", pythonDir); got {
		t.Error("minor 3.1 must not match a 3.12 install")
	}
}

func TestCopyTreePreservesLikeCpPR(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	mt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, "bin", "deep"), 0o755))
	must(os.WriteFile(filepath.Join(src, "bin", "tool"), []byte("exec"), 0o755))
	must(os.WriteFile(filepath.Join(src, "bin", "deep", "data"), []byte("d"), 0o640))
	must(os.Symlink("../outside", filepath.Join(src, "bin", "link")))
	must(os.Symlink("tool", filepath.Join(src, "bin", "rel")))
	must(os.Chtimes(filepath.Join(src, "bin", "tool"), mt, mt))
	must(os.Chmod(filepath.Join(src, "bin", "deep"), 0o500)) // read-only directory
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(src, "bin", "deep"), 0o700) })

	dst := filepath.Join(root, "dst")
	must(uvenv.CopyTree(src, dst))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dst, "bin", "deep"), 0o700) })

	if b, _ := os.ReadFile(filepath.Join(dst, "bin", "deep", "data")); string(b) != "d" {
		t.Errorf("content: %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dst, "bin", "tool"))
	if fi.Mode().Perm() != 0o755 || !fi.ModTime().Equal(mt) {
		t.Errorf("file mode/time not preserved: %v %v", fi.Mode().Perm(), fi.ModTime())
	}
	if fi, _ := os.Stat(filepath.Join(dst, "bin", "deep")); fi.Mode().Perm() != 0o500 {
		t.Errorf("read-only directory mode not preserved: %v", fi.Mode().Perm())
	}
	if l, err := os.Readlink(filepath.Join(dst, "bin", "link")); err != nil || l != "../outside" {
		t.Errorf("a dangling link must be copied as a link, got %q %v", l, err)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "bin", "rel")); l != "tool" {
		t.Errorf("relative link rewritten: %q", l)
	}
}
