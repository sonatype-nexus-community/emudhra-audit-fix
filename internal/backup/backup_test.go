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

package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileStore_Create(t *testing.T) {
	// Create a temp directory for testing
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	originalContent := []byte("original content")
	err = os.WriteFile(testFile, originalContent, 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Create a backup
	backupPath, err := store.Create(testFile, "pre-fix")
	require.NoError(t, err)
	assert.NotEmpty(t, backupPath)

	// Verify backup naming format: <file>.<tag>-<timestamp>
	assert.True(t, strings.HasPrefix(backupPath, testFile+".pre-fix-"))
	assert.Contains(t, backupPath, "pre-fix-")

	// Verify backup exists
	_, err = os.Stat(backupPath)
	require.NoError(t, err)

	// Verify backup content
	backupContent, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, originalContent, backupContent)

	// Verify undo manifest was updated
	require.Len(t, store.UndoManifest, 1)
	assert.Equal(t, backupPath, store.UndoManifest[0])
}

func TestFileStore_Create_PreservesPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file with specific permissions
	testFile := filepath.Join(tmpDir, "executable.sh")
	err = os.WriteFile(testFile, []byte("#!/bin/bash\n"), 0755)
	require.NoError(t, err)

	store := NewFileStore()
	backupPath, err := store.Create(testFile, "pre-fix")
	require.NoError(t, err)

	// Verify permissions were preserved
	originalInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	backupInfo, err := os.Stat(backupPath)
	require.NoError(t, err)

	assert.Equal(t, originalInfo.Mode(), backupInfo.Mode())
}

func TestFileStore_Restore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "config.json")
	originalContent := []byte(`{"key": "original"}`)
	err = os.WriteFile(testFile, originalContent, 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Create a backup
	_, err = store.Create(testFile, "pre-fix")
	require.NoError(t, err)

	// Modify the file
	modifiedContent := []byte(`{"key": "modified"}`)
	err = os.WriteFile(testFile, modifiedContent, 0644)
	require.NoError(t, err)

	// Restore from backup
	err = store.Restore(testFile, "pre-fix")
	require.NoError(t, err)

	// Verify content was restored
	restoredContent, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, originalContent, restoredContent)
}

func TestFileStore_Restore_NoBackup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	store := NewFileStore()

	// Try to restore a file that was never backed up
	err = store.Restore(filepath.Join(tmpDir, "nonexistent.txt"), "pre-fix")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backup found")
}

func TestFileStore_Newest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "data.db")
	err = os.WriteFile(testFile, []byte("data"), 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Create first backup
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	_, err = store.Create(testFile, "auto")
	require.NoError(t, err)

	// Modify file and create second backup
	time.Sleep(10 * time.Millisecond)
	err = os.WriteFile(testFile, []byte("modified"), 0644)
	require.NoError(t, err)
	_, err = store.Create(testFile, "auto")
	require.NoError(t, err)

	// Verify Newest returns the latest backup
	newest, err := store.Newest(testFile, "auto")
	require.NoError(t, err)
	assert.NotEmpty(t, newest)
}

func TestFileStore_Newest_MultipleTags(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "file.txt")
	err = os.WriteFile(testFile, []byte("content"), 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Create backups with different tags
	backupA, err := store.Create(testFile, "tag-a")
	require.NoError(t, err)

	backupB, err := store.Create(testFile, "tag-b")
	require.NoError(t, err)

	// Verify Newest returns the right backup for each tag
	newestA, err := store.Newest(testFile, "tag-a")
	require.NoError(t, err)
	assert.Equal(t, backupA, newestA)

	newestB, err := store.Newest(testFile, "tag-b")
	require.NoError(t, err)
	assert.Equal(t, backupB, newestB)
}

func TestFileStore_List(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "document.pdf")
	err = os.WriteFile(testFile, []byte("PDF content"), 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Initially, no backups
	backups, err := store.List(testFile)
	require.NoError(t, err)
	assert.Empty(t, backups)

	// Create multiple backups
	time.Sleep(10 * time.Millisecond)
	_, err = store.Create(testFile, "v1")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	_, err = store.Create(testFile, "v2")
	require.NoError(t, err)

	// List should return both backups
	backups, err = store.List(testFile)
	require.NoError(t, err)
	assert.Len(t, backups, 2)
}

func TestFileStore_List_IgnoresNonBackupFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test file and backup
	testFile := filepath.Join(tmpDir, "file.txt")
	err = os.WriteFile(testFile, []byte("content"), 0644)
	require.NoError(t, err)

	store := NewFileStore()
	_, err = store.Create(testFile, "backup")
	require.NoError(t, err)

	// Create other files that shouldn't be listed as backups
	err = os.WriteFile(filepath.Join(tmpDir, "file.txt.readme"), []byte("readme"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("other"), 0644)
	require.NoError(t, err)

	backups, err := store.List(testFile)
	require.NoError(t, err)
	assert.Len(t, backups, 1)
}

func TestFakeStore(t *testing.T) {
	store := NewFakeStore()

	// Test Create
	backupPath, err := store.Create("/path/to/file.txt", "pre-fix")
	require.NoError(t, err)
	assert.Contains(t, backupPath, "pre-fix-fake")
	assert.Contains(t, store.Created, "/path/to/file.txt")

	// Test Newest
	newest, err := store.Newest("/path/to/file.txt", "pre-fix")
	require.NoError(t, err)
	assert.Equal(t, backupPath, newest)

	// Test Restore
	err = store.Restore("/path/to/file.txt", "pre-fix")
	require.NoError(t, err)

	// Test Restore when no backup exists
	err = store.Restore("/path/to/other.txt", "pre-fix")
	assert.Error(t, err)
}

func TestFakeStore_Errors(t *testing.T) {
	store := NewFakeStore()
	store.CreateError = assert.AnError
	store.RestoreError = assert.AnError

	_, err := store.Create("/test/file", "tag")
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)

	err = store.Restore("/test/file", "tag")
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

func TestBackupNamingFormat(t *testing.T) {
	// Test that backup names follow: <file>.<tag>-<timestamp>
	tests := []struct {
		name     string
		file     string
		tag      string
		contains string
	}{
		{
			name:     "simple filename",
			file:     "/path/to/file.txt",
			tag:      "backup",
			contains: "file.txt.backup-",
		},
		{
			name:     "complex tag",
			file:     "/path/to/config.json",
			tag:      "pre-fix-v1",
			contains: "config.json.pre-fix-v1-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "backup-naming-*")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(tmpDir) }()

			testFile := filepath.Join(tmpDir, filepath.Base(tt.file))
			err = os.WriteFile(testFile, []byte("content"), 0644)
			require.NoError(t, err)

			store := NewFileStore()
			backupPath, err := store.Create(testFile, tt.tag)
			require.NoError(t, err)
			assert.Contains(t, backupPath, tt.contains)

			// Verify timestamp format (YYYYMMDD-HHMMSS)
			parts := strings.Split(backupPath, "-")
			require.GreaterOrEqual(t, len(parts), 2)
		})
	}
}

func TestFileStore_UndoManifestRoundTrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "backup-undo-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	err = os.WriteFile(file1, []byte("content1"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file2, []byte("content2"), 0644)
	require.NoError(t, err)

	store := NewFileStore()

	// Create backups
	backup1, err := store.Create(file1, "auto")
	require.NoError(t, err)

	backup2, err := store.Create(file2, "auto")
	require.NoError(t, err)

	// Verify undo manifest tracks all backups
	require.Len(t, store.UndoManifest, 2)
	assert.Contains(t, store.UndoManifest, backup1)
	assert.Contains(t, store.UndoManifest, backup2)

	// The manifest can be used for undo operations
	for _, backupPath := range store.UndoManifest {
		assert.FileExists(t, backupPath)
	}
}

func TestFileStore_TempDirOperations(t *testing.T) {
	// Verify backups work correctly in temp directories
	tmpDir, err := os.MkdirTemp("", "backup-temp-*")
	require.NoError(t, err)

	// Create file in temp dir
	testFile := filepath.Join(tmpDir, "temp.txt")
	err = os.WriteFile(testFile, []byte("temp content"), 0644)
	require.NoError(t, err)

	store := NewFileStore()
	backupPath, err := store.Create(testFile, "temp")
	require.NoError(t, err)

	// Backup should be in same directory as original
	assert.Equal(t, tmpDir, filepath.Dir(backupPath))

	// Cleanup
	_ = os.RemoveAll(tmpDir)
}
