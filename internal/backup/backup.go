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

// Package backup handles backup naming, restore, and undo manifest.
// Backup format: '<file>.<tag>-<stamp>'
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Store manages backups and restoration.
type Store interface {
	// Create creates a backup of a file with the given tag.
	// Returns the backup path.
	Create(path, tag string) (string, error)

	// Restore restores a file from its most recent backup with the given tag.
	Restore(path, tag string) error

	// Newest returns the most recent backup path for a file with the given tag.
	Newest(path, tag string) (string, error)

	// List returns all backups for a file.
	List(path string) ([]string, error)
}

// FileStore is a file-based backup store.
type FileStore struct {
	// UndoManifest tracks backups for undo operations.
	UndoManifest []string
}

// NewFileStore creates a new FileStore.
func NewFileStore() *FileStore {
	return &FileStore{
		UndoManifest: make([]string, 0),
	}
}

// Create creates a backup of a file.
func (s *FileStore) Create(path, tag string) (string, error) {
	// Ensure source exists
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot stat %s: %w", path, err)
	}

	// Create backup name: <path>.<tag>-<timestamp>
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s-%s", path, tag, timestamp)

	// Copy file
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	if err := os.WriteFile(backupPath, data, info.Mode()); err != nil {
		return "", fmt.Errorf("cannot write backup %s: %w", backupPath, err)
	}

	// Record in undo manifest
	s.UndoManifest = append(s.UndoManifest, backupPath)

	return backupPath, nil
}

// Restore restores a file from its most recent backup.
func (s *FileStore) Restore(path, tag string) error {
	backupPath, err := s.Newest(path, tag)
	if err != nil {
		return err
	}

	// Read backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("cannot read backup %s: %w", backupPath, err)
	}

	// Get backup permissions
	info, err := os.Stat(backupPath)
	if err != nil {
		return fmt.Errorf("cannot stat backup %s: %w", backupPath, err)
	}

	// Write to original location
	if err := os.WriteFile(path, data, info.Mode()); err != nil {
		return fmt.Errorf("cannot restore %s: %w", path, err)
	}

	return nil
}

// Newest returns the most recent backup for a file with the given tag.
func (s *FileStore) Newest(path, tag string) (string, error) {
	backups, err := s.List(path)
	if err != nil {
		return "", err
	}

	// Filter by tag
	var matching []string
	prefix := fmt.Sprintf("%s.%s-", path, tag)
	for _, backup := range backups {
		if strings.HasPrefix(backup, prefix) {
			matching = append(matching, backup)
		}
	}

	if len(matching) == 0 {
		return "", fmt.Errorf("no backup found for %s with tag %s", path, tag)
	}

	// Sort and return newest (last in sorted order)
	sort.Strings(matching)
	return matching[len(matching)-1], nil
}

// List returns all backups for a file.
func (s *FileStore) List(path string) ([]string, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory %s: %w", dir, err)
	}

	var backups []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Check if this is a backup of the file
		if strings.HasPrefix(entry.Name(), base+".") {
			// Check if it matches the backup pattern: <name>.<tag>-<timestamp>
			parts := strings.SplitN(entry.Name(), ".", 2)
			if len(parts) == 2 && len(strings.Split(parts[1], "-")) >= 2 {
				backups = append(backups, filepath.Join(dir, entry.Name()))
			}
		}
	}

	return backups, nil
}

// FakeStore is a test implementation of Store.
type FakeStore struct {
	// Backups maps original paths to their backup paths.
	Backups map[string]string

	// CreateError is the error to return from Create (if any).
	CreateError error

	// RestoreError is the error to return from Restore (if any).
	RestoreError error

	// Created tracks all Create calls.
	Created []string
}

// NewFakeStore creates a new FakeStore.
func NewFakeStore() *FakeStore {
	return &FakeStore{
		Backups: make(map[string]string),
		Created: make([]string, 0),
	}
}

// Create records the backup request.
func (f *FakeStore) Create(path, tag string) (string, error) {
	if f.CreateError != nil {
		return "", f.CreateError
	}
	backupPath := fmt.Sprintf("%s.%s-fake", path, tag)
	f.Backups[path] = backupPath
	f.Created = append(f.Created, path)
	return backupPath, nil
}

// Restore restores from the fake backup.
func (f *FakeStore) Restore(path, tag string) error {
	if f.RestoreError != nil {
		return f.RestoreError
	}
	if _, ok := f.Backups[path]; !ok {
		return fmt.Errorf("no backup for %s", path)
	}
	return nil
}

// Newest returns the fake backup path.
func (f *FakeStore) Newest(path, tag string) (string, error) {
	if backupPath, ok := f.Backups[path]; ok {
		return backupPath, nil
	}
	return "", fmt.Errorf("no backup for %s", path)
}

// List returns empty list in fake.
func (f *FakeStore) List(path string) ([]string, error) {
	if backupPath, ok := f.Backups[path]; ok {
		return []string{backupPath}, nil
	}
	return []string{}, nil
}
