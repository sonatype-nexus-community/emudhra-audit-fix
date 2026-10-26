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
	"syscall"
	"testing"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvenv"
)

func TestUVStorageDevice(t *testing.T) {
	t.Run("returns device ID for existing path", func(t *testing.T) {
		tmpDir := t.TempDir()

		dev := uvenv.UVStorageDevice(tmpDir)
		if dev == -1 {
			t.Fatal("Expected valid device ID, got -1")
		}

		// Verify it matches syscall.Stat
		var stat syscall.Stat_t
		if err := syscall.Stat(tmpDir, &stat); err != nil {
			t.Fatal(err)
		}
		if dev != int64(stat.Dev) {
			t.Errorf("Expected device %d, got %d", stat.Dev, dev)
		}
	})

	t.Run("returns -1 for non-existent path", func(t *testing.T) {
		dev := uvenv.UVStorageDevice("/nonexistent/path")
		if dev != -1 {
			t.Errorf("Expected -1 for non-existent path, got %d", dev)
		}
	})

	t.Run("same device for paths on same filesystem", func(t *testing.T) {
		tmpDir := t.TempDir()
		dir1 := filepath.Join(tmpDir, "dir1")
		dir2 := filepath.Join(tmpDir, "dir2")

		if err := os.Mkdir(dir1, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir2, 0755); err != nil {
			t.Fatal(err)
		}

		dev1 := uvenv.UVStorageDevice(dir1)
		dev2 := uvenv.UVStorageDevice(dir2)

		if dev1 != dev2 {
			t.Errorf("Expected same device ID, got %d and %d", dev1, dev2)
		}
	})
}

func TestUVPrepareBackups(t *testing.T) {
	t.Run("creates backup directory if it does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		source := filepath.Join(tmpDir, "source")
		backupRoot := filepath.Join(tmpDir, "backup")

		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}

		if err := uvenv.UVPrepareBackups(source, backupRoot, nil); err != nil {
			t.Fatalf("UVPrepareBackups failed: %v", err)
		}

		// Verify backup directory was created with correct permissions
		info, err := os.Stat(backupRoot)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Error("Expected backup root to be a directory")
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Expected permissions 0700, got %04o", info.Mode().Perm())
		}
	})

	t.Run("refuses substituted symlink backup root", func(t *testing.T) {
		tmpDir := t.TempDir()
		source := filepath.Join(tmpDir, "source")
		unrelatedDir := filepath.Join(tmpDir, "unrelated")
		backupRoot := filepath.Join(tmpDir, "backup")

		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(unrelatedDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlink that points to unrelated directory
		if err := os.Symlink(unrelatedDir, backupRoot); err != nil {
			t.Fatal(err)
		}

		err := uvenv.UVPrepareBackups(source, backupRoot, nil)
		if err == nil {
			t.Fatal("Expected error for symlink backup root")
		}
		if err.Error() != "backup root is a symlink: "+backupRoot {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("refuses backup root with wrong permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		source := filepath.Join(tmpDir, "source")
		backupRoot := filepath.Join(tmpDir, "backup")

		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(backupRoot, 0777); err != nil {
			t.Fatal(err)
		}
		// Explicitly set permissions to 0777 (override umask)
		if err := os.Chmod(backupRoot, 0777); err != nil {
			t.Fatal(err)
		}

		err := uvenv.UVPrepareBackups(source, backupRoot, nil)
		if err == nil {
			t.Fatal("Expected error for insecure permissions")
		}
		// Should mention insecure permissions
		if err.Error() != "backup root has insecure permissions: 0777" {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("refuses cross-device backup", func(t *testing.T) {
		// This test kills mutation: "skip the same-device check"
		// We simulate cross-device by mocking storageDeviceFunc
		tmpDir := t.TempDir()
		source := filepath.Join(tmpDir, "source")
		backupRoot := filepath.Join(tmpDir, "backup")

		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}

		// Create backup directory with correct permissions
		if err := os.Mkdir(backupRoot, 0700); err != nil {
			t.Fatal(err)
		}

		// Save original function
		origFunc := uvenv.StorageDeviceFunc
		defer func() { uvenv.StorageDeviceFunc = origFunc }()

		// Mock to return different device IDs
		uvenv.StorageDeviceFunc = func(path string) int64 {
			// Return different device ID for the backup root specifically
			if path == backupRoot {
				return 2 // Different device
			}
			return 1 // Source device
		}

		err := uvenv.UVPrepareBackups(source, backupRoot, nil)
		if err == nil {
			t.Fatal("Expected error for cross-device backup")
		}
		if !strings.Contains(err.Error(), "different device") {
			t.Errorf("Expected 'different device' error, got: %v", err)
		}
	})

	t.Run("accepts disk space checker", func(t *testing.T) {
		tmpDir := t.TempDir()
		source := filepath.Join(tmpDir, "source")
		backupRoot := filepath.Join(tmpDir, "backup")

		if err := os.Mkdir(source, 0755); err != nil {
			t.Fatal(err)
		}

		checkerCalled := false
		checkSpace := func(path string) (uint64, error) {
			checkerCalled = true
			return 1024 * 1024 * 1024, nil // 1GB available
		}

		if err := uvenv.UVPrepareBackups(source, backupRoot, checkSpace); err != nil {
			t.Fatalf("UVPrepareBackups failed: %v", err)
		}

		if !checkerCalled {
			t.Error("Disk space checker was not called")
		}
	})
}

func TestUVSavePythonInstalls(t *testing.T) {
	t.Run("saves matching Python installations", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		backupDir := filepath.Join(tmpDir, "backup")

		// Create Python installations
		install312 := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none")
		install313 := filepath.Join(pythonDir, "cpython-3.13.0-macos-aarch64-none")

		if err := os.MkdirAll(filepath.Join(install312, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(install313, "bin"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create files in the installations
		python312 := filepath.Join(install312, "bin", "python3")
		if err := os.WriteFile(python312, []byte("#!/bin/sh\necho 3.12.0"), 0755); err != nil {
			t.Fatal(err)
		}

		python313 := filepath.Join(install313, "bin", "python3")
		if err := os.WriteFile(python313, []byte("#!/bin/sh\necho 3.13.0"), 0755); err != nil {
			t.Fatal(err)
		}

		// Save only 3.12 installations
		if err := uvenv.UVSavePythonInstalls(pythonDir, "3.12", backupDir); err != nil {
			t.Fatalf("UVSavePythonInstalls failed: %v", err)
		}

		// Verify only 3.12 was backed up
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("Expected 1 backed up installation, got %d", len(entries))
		}
		if entries[0].Name() != "cpython-3.12.0-macos-aarch64-none" {
			t.Errorf("Unexpected backup: %s", entries[0].Name())
		}

		// Verify backed up file exists
		backedUpPython := filepath.Join(backupDir, "cpython-3.12.0-macos-aarch64-none", "bin", "python3")
		content, err := os.ReadFile(backedUpPython)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "#!/bin/sh\necho 3.12.0" {
			t.Errorf("Unexpected content: %s", string(content))
		}
	})

	t.Run("refuses to backup symlink installations", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		backupDir := filepath.Join(tmpDir, "backup")

		if err := os.MkdirAll(pythonDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a symlink as an installation (should not be backed up)
		targetDir := filepath.Join(tmpDir, "target")
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			t.Fatal(err)
		}

		symlinkPath := filepath.Join(pythonDir, "cpython-3.12.0-symlink")
		if err := os.Symlink(targetDir, symlinkPath); err != nil {
			t.Fatal(err)
		}

		err := uvenv.UVSavePythonInstalls(pythonDir, "3.12", backupDir)
		if err == nil {
			t.Fatal("Expected error when backing up symlink")
		}
	})
}

func TestUVRestorePythonInstalls(t *testing.T) {
	t.Run("restores Python installations from backup", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		backupDir := filepath.Join(tmpDir, "backup")
		installationsDir := filepath.Join(backupDir, "installations")

		// Create backup with a saved installation
		savedInstall := filepath.Join(installationsDir, "cpython-3.12.0-macos-aarch64-none")
		if err := os.MkdirAll(filepath.Join(savedInstall, "bin"), 0755); err != nil {
			t.Fatal(err)
		}

		python312 := filepath.Join(savedInstall, "bin", "python3")
		if err := os.WriteFile(python312, []byte("#!/bin/sh\necho saved"), 0755); err != nil {
			t.Fatal(err)
		}

		// Restore
		if err := uvenv.UVRestorePythonInstalls(pythonDir, backupDir); err != nil {
			t.Fatalf("UVRestorePythonInstalls failed: %v", err)
		}

		// Verify installation was restored
		restoredPython := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none", "bin", "python3")
		content, err := os.ReadFile(restoredPython)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "#!/bin/sh\necho saved" {
			t.Errorf("Unexpected content: %s", string(content))
		}
	})

	t.Run("moves failed installations to failed-installations", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		backupDir := filepath.Join(tmpDir, "backup")
		installationsDir := filepath.Join(backupDir, "installations")

		// Create an existing failed installation
		failedInstall := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none")
		if err := os.MkdirAll(failedInstall, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(failedInstall, "failed"), []byte("failed"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create backup with saved installation
		savedInstall := filepath.Join(installationsDir, "cpython-3.12.0-macos-aarch64-none")
		if err := os.MkdirAll(savedInstall, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(savedInstall, "saved"), []byte("saved"), 0644); err != nil {
			t.Fatal(err)
		}

		// Restore
		if err := uvenv.UVRestorePythonInstalls(pythonDir, backupDir); err != nil {
			t.Fatalf("UVRestorePythonInstalls failed: %v", err)
		}

		// Verify failed installation was moved
		failedPath := filepath.Join(backupDir, "failed-installations", "cpython-3.12.0-macos-aarch64-none", "failed")
		content, err := os.ReadFile(failedPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "failed" {
			t.Errorf("Unexpected failed content: %s", string(content))
		}

		// Verify saved installation was restored
		savedPath := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none", "saved")
		content, err = os.ReadFile(savedPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "saved" {
			t.Errorf("Unexpected saved content: %s", string(content))
		}
	})
}

func TestUVRestoreTool(t *testing.T) {
	t.Run("restores tool environment from backup", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")

		// Create saved environment
		savedEnv := filepath.Join(backupDir, "environment")
		if err := os.MkdirAll(savedEnv, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(savedEnv, "saved"), []byte("saved"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create backup bin links
		binLinksBackup := filepath.Join(backupDir, "bin-links")
		if err := os.MkdirAll(binLinksBackup, 0755); err != nil {
			t.Fatal(err)
		}

		// The symlink should point to where the file will be AFTER restore
		cliFile := filepath.Join(toolDir, "alpha-cli")
		if err := os.WriteFile(filepath.Join(savedEnv, "alpha-cli"), []byte("saved cli"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlink in backup
		if err := os.Symlink(cliFile, filepath.Join(binLinksBackup, "alpha-cli")); err != nil {
			t.Fatal(err)
		}

		// Create bin directory
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Restore
		if err := uvenv.UVRestoreTool(toolDir, binDir, backupDir); err != nil {
			t.Fatalf("UVRestoreTool failed: %v", err)
		}

		// Verify environment was restored
		content, err := os.ReadFile(filepath.Join(toolDir, "saved"))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "saved" {
			t.Errorf("Unexpected content: %s", string(content))
		}

		// Verify link was restored
		linkTarget, err := os.Readlink(filepath.Join(binDir, "alpha-cli"))
		if err != nil {
			t.Fatal(err)
		}
		expectedTarget := filepath.Join(toolDir, "alpha-cli")
		if linkTarget != expectedTarget {
			t.Errorf("Expected link target %s, got %s", expectedTarget, linkTarget)
		}
	})

	t.Run("preserves failed environment", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		backupDir := filepath.Join(tmpDir, "backup")

		// Create failed environment
		if err := os.MkdirAll(toolDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(toolDir, "failed"), []byte("failed"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create saved environment
		savedEnv := filepath.Join(backupDir, "environment")
		if err := os.MkdirAll(savedEnv, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(savedEnv, "saved"), []byte("saved"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create bin directory and backup links
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(backupDir, "bin-links"), 0755); err != nil {
			t.Fatal(err)
		}

		// Restore
		if err := uvenv.UVRestoreTool(toolDir, binDir, backupDir); err != nil {
			t.Fatalf("UVRestoreTool failed: %v", err)
		}

		// Verify failed environment was preserved
		failedPath := filepath.Join(backupDir, "failed-environment", "failed")
		content, err := os.ReadFile(failedPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "failed" {
			t.Errorf("Unexpected failed content: %s", string(content))
		}

		// Verify saved environment was restored
		savedPath := filepath.Join(toolDir, "saved")
		content, err = os.ReadFile(savedPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "saved" {
			t.Errorf("Unexpected saved content: %s", string(content))
		}
	})
}

func TestUVToolEntrypointsSafe(t *testing.T) {
	t.Run("accepts safe entrypoints", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")

		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create tool binary
		cliFile := filepath.Join(toolDir, "bin", "alpha-cli")
		if err := os.WriteFile(cliFile, []byte("cli"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlink
		if err := os.Symlink(cliFile, filepath.Join(binDir, "alpha-cli")); err != nil {
			t.Fatal(err)
		}

		// Create listing
		listing := `alpha v1.0 (` + toolDir + `)
- alpha-cli (` + filepath.Join(binDir, "alpha-cli") + `)
`

		safe, err := uvenv.UVToolEntrypointsSafe("alpha", toolDir, binDir, listing)
		if err != nil {
			t.Fatalf("UVToolEntrypointsSafe failed: %v", err)
		}
		if !safe {
			t.Error("Expected entrypoints to be safe")
		}
	})

	t.Run("refuses entrypoint outside bindir", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		otherDir := filepath.Join(tmpDir, "other")

		if err := os.MkdirAll(toolDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(otherDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create listing with entrypoint outside bindir
		listing := `alpha v1.0 (` + toolDir + `)
- alpha-cli (` + filepath.Join(otherDir, "alpha-cli") + `)
`

		_, err := uvenv.UVToolEntrypointsSafe("alpha", toolDir, binDir, listing)
		if err == nil {
			t.Fatal("Expected error for entrypoint outside bindir")
		}
	})

	t.Run("refuses entrypoint that escapes tool directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		toolDir := filepath.Join(tmpDir, "tools", "alpha")
		binDir := filepath.Join(tmpDir, "bin")
		otherToolDir := filepath.Join(tmpDir, "tools", "beta")

		if err := os.MkdirAll(filepath.Join(toolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(otherToolDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create binary in other tool
		otherCli := filepath.Join(otherToolDir, "bin", "beta-cli")
		if err := os.WriteFile(otherCli, []byte("other"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create symlink pointing to other tool
		if err := os.Symlink(otherCli, filepath.Join(binDir, "alpha-cli")); err != nil {
			t.Fatal(err)
		}

		// Create listing
		listing := `alpha v1.0 (` + toolDir + `)
- alpha-cli (` + filepath.Join(binDir, "alpha-cli") + `)
`

		_, err := uvenv.UVToolEntrypointsSafe("alpha", toolDir, binDir, listing)
		if err == nil {
			t.Fatal("Expected error for entrypoint that escapes tool directory")
		}
	})
}
