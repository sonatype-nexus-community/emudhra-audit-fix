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

// Package exec provides a Runner interface wrapping os/exec (real + fake), with timeouts.
// This enables testability; all command execution goes through this interface.
package exec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CommandResult holds the result of a command execution.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
}

// Runner is an interface for executing commands, allowing for both real and fake implementations.
type Runner interface {
	// Run executes a command with the given arguments and returns the output.
	// It respects context cancellation and implements timeouts.
	Run(ctx context.Context, name string, args ...string) CommandResult

	// RunWithInput executes a command with stdin input.
	RunWithInput(ctx context.Context, input string, name string, args ...string) CommandResult

	// RunWithTimeout executes a command with a specific timeout duration.
	RunWithTimeout(timeout time.Duration, name string, args ...string) CommandResult

	// RunWithDir executes a command in a specific working directory.
	RunWithDir(ctx context.Context, dir string, name string, args ...string) CommandResult

	// RunWithEnv executes a command with additional environment variables.
	RunWithEnv(ctx context.Context, env []string, name string, args ...string) CommandResult

	// RunAttached executes a command with stdio attached to the process (for sudo and interactive tools).
	// This is needed for sudo to prompt on /dev/tty itself.
	RunAttached(ctx context.Context, name string, args ...string) error
}

// RealRunner is the real implementation that executes commands via os/exec.
type RealRunner struct {
	// Env is additional environment variables to set for all commands.
	Env []string

	// Dir is the working directory for all commands (empty means current directory).
	Dir string
}

// NewRealRunner creates a new RealRunner.
func NewRealRunner() *RealRunner {
	return &RealRunner{}
}

// Run executes a command and captures stdout/stderr separately.
func (r *RealRunner) Run(ctx context.Context, name string, args ...string) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)

	// Set working directory if specified
	if r.Dir != "" {
		cmd.Dir = r.Dir
	}

	// Set environment if specified
	if r.Env != nil {
		cmd.Env = append(os.Environ(), r.Env...)
	}

	// Capture stdout and stderr separately
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Error:    err,
	}
}

// RunWithInput executes a command with stdin input.
func (r *RealRunner) RunWithInput(ctx context.Context, input string, name string, args ...string) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)

	// Set working directory if specified
	if r.Dir != "" {
		cmd.Dir = r.Dir
	}

	// Set environment if specified
	if r.Env != nil {
		cmd.Env = append(os.Environ(), r.Env...)
	}

	// Set stdin
	cmd.Stdin = strings.NewReader(input)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Error:    err,
	}
}

// RunWithTimeout executes a command with a specific timeout duration.
// This ports run_to() from the bash script (lines 169-182).
func (r *RealRunner) RunWithTimeout(timeout time.Duration, name string, args ...string) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return r.Run(ctx, name, args...)
}

// RunWithDir executes a command in a specific working directory.
func (r *RealRunner) RunWithDir(ctx context.Context, dir string, name string, args ...string) CommandResult {
	runner := &RealRunner{Dir: dir}
	return runner.Run(ctx, name, args...)
}

// RunWithEnv executes a command with additional environment variables.
func (r *RealRunner) RunWithEnv(ctx context.Context, env []string, name string, args ...string) CommandResult {
	runner := &RealRunner{Env: env}
	return runner.Run(ctx, name, args...)
}

// RunAttached executes a command with stdio attached to the process.
// This is needed for sudo to prompt on /dev/tty itself.
// Returns nil on success (exit code 0), or an error on failure.
func (r *RealRunner) RunAttached(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

	// Set working directory if specified
	if r.Dir != "" {
		cmd.Dir = r.Dir
	}

	// Set environment if specified
	if r.Env != nil {
		cmd.Env = append(os.Environ(), r.Env...)
	}

	// Attach stdin, stdout, stderr to the process
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
