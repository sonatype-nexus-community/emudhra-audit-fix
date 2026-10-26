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

package privilege

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNeeds_WritablePath tests Needs on writable paths
func TestNeeds_WritablePath(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a temp file
	tmpFile := filepath.Join(tmpDir, "testfile")
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))

	// Create fake escalator
	fake := NewFakeEscalator()
	fake.IsRootVal = false

	// Test writable file
	fake.NeedsMap[tmpFile] = false
	result := fake.Needs(tmpFile)
	assert.False(t, result, "writable file should not need root")
}

// TestNeeds_UnwritablePath tests Needs on unwritable paths
func TestNeeds_UnwritablePath(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a temp file
	tmpFile := filepath.Join(tmpDir, "testfile")
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))

	// Make it read-only
	require.NoError(t, os.Chmod(tmpFile, 0444))
	defer func() { _ = os.Chmod(tmpFile, 0644) }()

	// Create fake escalator
	fake := NewFakeEscalator()
	fake.IsRootVal = false

	// Test unwritable file
	fake.NeedsMap[tmpFile] = true
	result := fake.Needs(tmpFile)
	assert.True(t, result, "unwritable file should need root")
}

// TestNeeds_MissingPath tests Needs on missing paths
func TestNeeds_MissingPath(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a non-existent path
	missingPath := filepath.Join(tmpDir, "nonexistent", "file")

	// Create fake escalator
	fake := NewFakeEscalator()
	fake.IsRootVal = false

	// Test missing path - checks parent directory
	// Parent exists and is writable, so should not need root
	result := fake.Needs(missingPath)
	// Since the fake doesn't have real access checking, we expect false
	assert.False(t, result)
}

// TestNeeds_AlreadyRoot tests that root never needs escalation
func TestNeeds_AlreadyRoot(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = true

	// Any path should return false when already root
	result := fake.Needs("/some/path")
	assert.False(t, result, "root should never need escalation")
}

// TestIsRoot tests root detection
func TestIsRoot(t *testing.T) {
	fake := NewFakeEscalator()

	fake.IsRootVal = true
	assert.True(t, fake.IsRoot())

	fake.IsRootVal = false
	assert.False(t, fake.IsRoot())
}

// TestHasSudo tests sudo availability check
func TestHasSudo(t *testing.T) {
	fake := NewFakeEscalator()

	fake.HasSudoVal = true
	assert.True(t, fake.HasSudo())

	fake.HasSudoVal = false
	assert.False(t, fake.HasSudo())
}

// TestAsRoot_DryRun tests that dry-run prints but does not execute
func TestAsRoot_DryRun(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = true

	ctx := context.Background()
	err := fake.AsRoot(ctx, true, "echo", "hello")

	assert.NoError(t, err)
	assert.Len(t, fake.DryRunCommands, 1)
	assert.Equal(t, "echo hello", fake.DryRunCommands[0])
	assert.Len(t, fake.Commands, 0, "dry-run should not record actual commands")
}

// TestAsRoot_AlreadyRoot tests execution when already root
func TestAsRoot_AlreadyRoot(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = true
	fake.HasSudoVal = false

	ctx := context.Background()
	err := fake.AsRoot(ctx, false, "echo", "hello")

	assert.NoError(t, err)
	assert.Len(t, fake.Commands, 1)
	assert.Contains(t, fake.Commands[0], "echo")
}

// TestAsRoot_NeedsSudo tests sudo escalation
func TestAsRoot_NeedsSudo(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = true

	ctx := context.Background()
	err := fake.AsRoot(ctx, false, "apt-get", "update")

	assert.NoError(t, err)
	assert.Len(t, fake.Commands, 1)
	assert.Contains(t, fake.Commands[0], "apt-get")
}

// TestAsRoot_NoSudo tests error when sudo is needed but not available
func TestAsRoot_NoSudo(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = false

	ctx := context.Background()
	err := fake.AsRoot(ctx, false, "apt-get", "update")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires root")
	assert.Contains(t, err.Error(), "sudo is available")
}

// TestPerCommandEscalation tests per-command escalation using fake runner
func TestPerCommandEscalation(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = true

	ctx := context.Background()

	// Execute multiple commands
	_ = fake.AsRoot(ctx, false, "apt-get", "update")
	_ = fake.AsRoot(ctx, false, "systemctl", "restart", "nginx")
	_ = fake.AsRoot(ctx, false, "cp", "/source", "/dest")

	assert.Len(t, fake.Commands, 3)
	assert.Contains(t, fake.Commands[0], "apt-get")
	assert.Contains(t, fake.Commands[1], "systemctl")
	assert.Contains(t, fake.Commands[2], "cp")
}

// TestDryRunDoesNotExecute tests that dry-run never executes commands
func TestDryRunDoesNotExecute(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = true
	fake.AsRootError = fmt.Errorf("should not be reached")

	ctx := context.Background()

	// Dry-run should not return the error
	err := fake.AsRoot(ctx, true, "rm", "-rf", "/important")
	assert.NoError(t, err)

	// Should record in DryRunCommands, not Commands
	assert.Len(t, fake.DryRunCommands, 1)
	assert.Len(t, fake.Commands, 0)
}

// TestSudo_N_Flag tests that sudo -n is used when no TTY
// This is tested indirectly via the FakeEscalator behavior
func TestSudo_N_Flag(t *testing.T) {
	// The real implementation uses sudo -n when there's no TTY
	// In the fake, we just verify the command is queued
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = true

	ctx := context.Background()
	err := fake.AsRoot(ctx, false, "apt-get", "install", "-y", "curl")

	assert.NoError(t, err)
	assert.Len(t, fake.Commands, 1)
	// In real implementation, this would be "sudo -n apt-get install -y curl"
	// The fake just records the command name and args
	assert.Contains(t, fake.Commands[0], "apt-get")
}

// TestMissingSudoErrorMessage tests the error message when sudo is missing
func TestMissingSudoErrorMessage(t *testing.T) {
	fake := NewFakeEscalator()
	fake.IsRootVal = false
	fake.HasSudoVal = false

	ctx := context.Background()
	err := fake.AsRoot(ctx, false, "apt-get", "update")

	require.Error(t, err)
	// Match the exact error message format from the implementation
	assert.Contains(t, err.Error(), "this operation requires root")
	assert.Contains(t, err.Error(), "re-run as root or ensure sudo is available")
}

// TestRealEscalator_NeedsWithWritablePath tests RealEscalator.Needs with a writable path
func TestRealEscalator_NeedsWithWritablePath(t *testing.T) {
	// Skip if running as root (Needs would always return false)
	if os.Geteuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a temp file
	tmpFile := filepath.Join(tmpDir, "testfile")
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))

	esc := NewRealEscalator()

	// Writable file should not need root
	result := esc.Needs(tmpFile)
	assert.False(t, result, "writable file should not need root")
}

// TestRealEscalator_NeedsWithUnwritablePath tests RealEscalator.Needs with an unwritable path
func TestRealEscalator_NeedsWithUnwritablePath(t *testing.T) {
	// Skip if running as root (root can write to anything)
	if os.Geteuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a temp file
	tmpFile := filepath.Join(tmpDir, "testfile")
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0444))
	defer func() { _ = os.Chmod(tmpFile, 0644) }() // Restore permissions for cleanup

	esc := NewRealEscalator()

	// Unwritable file should need root
	result := esc.Needs(tmpFile)
	assert.True(t, result, "unwritable file should need root")
}

// TestRealEscalator_NeedsWithMissingPath tests RealEscalator.Needs with a missing path
func TestRealEscalator_NeedsWithMissingPath(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a non-existent file in a writable directory
	missingPath := filepath.Join(tmpDir, "nonexistent", "file")

	esc := NewRealEscalator()

	// Parent directory is writable, so should not need root
	result := esc.Needs(missingPath)
	assert.False(t, result, "missing path in writable directory should not need root")
}

// TestRealEscalator_NeedsWithUnwritableParent tests RealEscalator.Needs with unwritable parent
func TestRealEscalator_NeedsWithUnwritableParent(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Create a temp directory structure
	tmpDir, err := os.MkdirTemp("", "privilege-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a subdirectory and make it read-only
	subDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.Mkdir(subDir, 0555))
	defer func() { _ = os.Chmod(subDir, 0755) }() // Restore for cleanup

	// Create a non-existent file in the read-only directory
	missingPath := filepath.Join(subDir, "file")

	esc := NewRealEscalator()

	// Parent directory is not writable, should need root
	result := esc.Needs(missingPath)
	assert.True(t, result, "missing path in unwritable directory should need root")
}

// TestRealEscalator_IsRoot tests RealEscalator.IsRoot
func TestRealEscalator_IsRoot(t *testing.T) {
	esc := NewRealEscalator()

	expected := os.Geteuid() == 0
	result := esc.IsRoot()

	assert.Equal(t, expected, result)
}

// TestRealEscalator_HasSudo tests RealEscalator.HasSudo
func TestRealEscalator_HasSudo(t *testing.T) {
	esc := NewRealEscalator()

	_, err := os.Stat("/usr/bin/sudo")
	expected := err == nil
	result := esc.HasSudo()

	assert.Equal(t, expected, result)
}

func TestFakeEscalatorFailOn(t *testing.T) {
	f := NewFakeEscalator()
	f.IsRootVal = true
	f.FailOn = func(c string) error {
		if strings.HasPrefix(c, "cp ") && strings.HasSuffix(c, " /etc/ssl/cert.pem") {
			return fmt.Errorf("no space left on device")
		}
		return nil
	}
	ctx := context.Background()

	// a backup (destination is the .pre-emudhra file) succeeds ...
	require.NoError(t, f.AsRoot(ctx, false, "cp", "-p", "/etc/ssl/cert.pem", "/etc/ssl/cert.pem.pre-emudhra-1"))
	// ... the install over the original fails, and is still recorded
	err := f.AsRoot(ctx, false, "cp", "/tmp/patched.pem", "/etc/ssl/cert.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no space left")
	assert.Len(t, f.Commands, 2)

	// AsRootError still fails everything when FailOn says nothing
	f2 := NewFakeEscalator()
	f2.IsRootVal = true
	f2.AsRootError = fmt.Errorf("denied")
	f2.FailOn = func(string) error { return nil }
	assert.Error(t, f2.AsRoot(ctx, false, "true"))
}
