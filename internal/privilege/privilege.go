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

// Package privilege handles sudo escalation and root checks.
// The binary never re-execs itself under sudo; escalation is per-command only.
package privilege

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
)

// Escalator provides privilege escalation functionality.
type Escalator interface {
	// Needs returns true if the path requires root to write.
	// Uses unix.Access(path, W_OK).
	Needs(path string) bool

	// IsRoot returns true if currently running as root.
	IsRoot() bool

	// HasSudo returns true if sudo is available.
	HasSudo() bool

	// AsRoot executes a command with sudo if needed, attaching stdio.
	// In dry-run mode, prints the command and returns nil without executing.
	// Returns an error if sudo is required but not available.
	AsRoot(ctx context.Context, dryRun bool, name string, args ...string) error
}

// RealEscalator is the real implementation.
type RealEscalator struct {
	runner  exec.Runner
	hasSudo bool
}

// NewRealEscalator creates a new RealEscalator.
func NewRealEscalator() *RealEscalator {
	hasSudo := false
	if _, err := os.Stat("/usr/bin/sudo"); err == nil {
		hasSudo = true
	}
	return &RealEscalator{
		runner:  exec.NewRealRunner(),
		hasSudo: hasSudo,
	}
}

// NewRealEscalatorWithRunner creates a new RealEscalator with a custom runner (for testing).
func NewRealEscalatorWithRunner(runner exec.Runner) *RealEscalator {
	hasSudo := false
	if _, err := os.Stat("/usr/bin/sudo"); err == nil {
		hasSudo = true
	}
	return &RealEscalator{
		runner:  runner,
		hasSudo: hasSudo,
	}
}

// Needs returns true if the path requires root to write.
// If the path doesn't exist, checks the parent directory.
func (e *RealEscalator) Needs(path string) bool {
	// If already root, never needs escalation
	if e.IsRoot() {
		return false
	}

	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		// Path doesn't exist, check parent directory
		parent := filepath.Dir(path)
		if parent == path {
			// Reached root, can't check further
			return true
		}
		return e.Needs(parent)
	}

	// If it's a directory, check it directly
	if info.IsDir() {
		err = unix.Access(path, unix.W_OK)
		return err != nil
	}

	// For files, check write access
	err = unix.Access(path, unix.W_OK)
	return err != nil
}

// IsRoot returns true if running as root.
func (e *RealEscalator) IsRoot() bool {
	return os.Geteuid() == 0
}

// HasSudo returns true if sudo is available.
func (e *RealEscalator) HasSudo() bool {
	return e.hasSudo
}

// AsRoot runs a command with sudo if needed, attaching stdio.
// This ports need_sudo()/as_root() from the bash script.
// In dry-run mode, prints the command (fx_cmd style) and does nothing.
func (e *RealEscalator) AsRoot(ctx context.Context, dryRun bool, name string, args ...string) error {
	// If already root, run directly
	if e.IsRoot() {
		if dryRun {
			fmt.Printf("[dry-run] would run: %s %v\n", name, args)
			return nil
		}
		return e.runner.RunAttached(ctx, name, args...)
	}

	// Need sudo
	if !e.hasSudo {
		return fmt.Errorf("this operation requires root; re-run as root or ensure sudo is available")
	}

	// Build sudo command
	sudoArgs := append([]string{name}, args...)

	if dryRun {
		fmt.Printf("[dry-run] would run: sudo %s %v\n", name, args)
		return nil
	}

	// Run with sudo, attaching stdio so sudo can prompt on /dev/tty
	return e.runner.RunAttached(ctx, "sudo", sudoArgs...)
}

// FakeEscalator is a test implementation.
type FakeEscalator struct {
	IsRootVal  bool
	HasSudoVal bool
	NeedsMap   map[string]bool

	// Commands records all commands passed to AsRoot.
	Commands []string

	// AsRootError is the error to return from every AsRoot call (if any).
	AsRootError error

	// FailOn, when set, is asked about each command line before it runs; a
	// non-nil result is returned as that command's error. It lets a test let a
	// backup succeed and then fail the install, which AsRootError (all or
	// nothing) cannot express. The failed command is still recorded in Commands.
	FailOn func(command string) error

	// DryRunCommands records all dry-run commands.
	DryRunCommands []string
}

// NewFakeEscalator creates a new FakeEscalator.
func NewFakeEscalator() *FakeEscalator {
	return &FakeEscalator{
		NeedsMap:       make(map[string]bool),
		Commands:       make([]string, 0),
		DryRunCommands: make([]string, 0),
	}
}

// Needs returns the scripted response for a path.
func (f *FakeEscalator) Needs(path string) bool {
	if f.IsRootVal {
		return false
	}
	if result, ok := f.NeedsMap[path]; ok {
		return result
	}
	return false
}

// IsRoot returns the scripted value.
func (f *FakeEscalator) IsRoot() bool {
	return f.IsRootVal
}

// HasSudo returns the scripted value.
func (f *FakeEscalator) HasSudo() bool {
	return f.HasSudoVal
}

// AsRoot records the command and returns the scripted error (or nil).
func (f *FakeEscalator) AsRoot(ctx context.Context, dryRun bool, name string, args ...string) error {
	// If already root, just record the command
	if f.IsRootVal {
		cmdStr := commandLine(name, args)
		if dryRun {
			f.DryRunCommands = append(f.DryRunCommands, cmdStr)
			return nil
		}
		f.Commands = append(f.Commands, cmdStr)
		return f.failure(cmdStr)
	}

	// Need sudo - if not available, return error
	if !f.HasSudoVal {
		return fmt.Errorf("this operation requires root; re-run as root or ensure sudo is available")
	}

	// Record sudo command
	cmdStr := commandLine(name, args)
	if dryRun {
		f.DryRunCommands = append(f.DryRunCommands, cmdStr)
		return nil
	}
	f.Commands = append(f.Commands, cmdStr)
	return f.failure(cmdStr)
}

// failure is the error to return for a command that has just been recorded.
func (f *FakeEscalator) failure(cmdStr string) error {
	if f.FailOn != nil {
		if err := f.FailOn(cmdStr); err != nil {
			return err
		}
	}
	return f.AsRootError
}

// commandLine renders a command as a shell would show it: the name followed by
// its arguments, space separated.
func commandLine(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
