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

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealRunner_Run_StdoutStderrSeparation(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	// Use /bin/sh to echo to stdout and stderr separately
	// This is portable across macOS and Linux
	result := runner.Run(ctx, "/bin/sh", "-c", "echo stdout-msg && echo stderr-msg >&2")

	require.NoError(t, result.Error)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Stdout, "stdout-msg")
	assert.Contains(t, result.Stderr, "stderr-msg")
	assert.NotContains(t, result.Stdout, "stderr-msg", "stderr should not be in stdout")
	assert.NotContains(t, result.Stderr, "stdout-msg", "stdout should not be in stderr")
}

func TestRealRunner_Run_ExitCodes(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	tests := []struct {
		name         string
		command      string
		args         []string
		wantExitCode int
		wantError    bool
	}{
		{
			name:         "exit code 0",
			command:      "/bin/sh",
			args:         []string{"-c", "exit 0"},
			wantExitCode: 0,
			wantError:    false,
		},
		{
			name:         "exit code 1",
			command:      "/bin/sh",
			args:         []string{"-c", "exit 1"},
			wantExitCode: 1,
			wantError:    true,
		},
		{
			name:         "exit code 42",
			command:      "/bin/sh",
			args:         []string{"-c", "exit 42"},
			wantExitCode: 42,
			wantError:    true,
		},
		{
			name:         "non-existent command",
			command:      "/nonexistent/command/that/does/not/exist",
			args:         []string{},
			wantExitCode: -1, // Command not found
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runner.Run(ctx, tt.command, tt.args...)
			assert.Equal(t, tt.wantExitCode, result.ExitCode)
			if tt.wantError {
				assert.Error(t, result.Error)
			} else {
				assert.NoError(t, result.Error)
			}
		})
	}
}

func TestRealRunner_Run_Stdin(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	// Use cat to echo stdin back to stdout
	input := "test-input-line-1\ntest-input-line-2\n"
	result := runner.RunWithInput(ctx, input, "/bin/cat")

	require.NoError(t, result.Error)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, input, result.Stdout)
}

func TestRealRunner_Run_ContextCancellation(t *testing.T) {
	runner := NewRealRunner()
	ctx, cancel := context.WithCancel(context.Background())

	// Start a long-running command
	cmdResult := make(chan CommandResult, 1)
	go func() {
		cmdResult <- runner.Run(ctx, "/bin/sleep", "10")
	}()

	// Cancel after a short delay
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Wait for result
	select {
	case result := <-cmdResult:
		assert.Error(t, result.Error)
		// Context cancellation should result in an error
		assert.True(t, errors.Is(result.Error, context.Canceled) || result.ExitCode != 0,
			"expected cancellation error or non-zero exit code")
	case <-time.After(2 * time.Second):
		t.Fatal("command did not respond to cancellation within 2 seconds")
	}
}

func TestRealRunner_Run_Timeout(t *testing.T) {
	runner := NewRealRunner()

	// RunWithTimeout with a 100ms timeout for a 10-second sleep
	result := runner.RunWithTimeout(100*time.Millisecond, "/bin/sleep", "10")

	assert.Error(t, result.Error)
	// The command should have been killed by the timeout
	assert.True(t, errors.Is(result.Error, context.DeadlineExceeded) || result.ExitCode != 0,
		"expected deadline exceeded error or non-zero exit code")
}

func TestRealRunner_Run_WorkingDirectory(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "exec-test-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a file in the temp directory
	testFile := "test-file.txt"
	err = os.WriteFile(filepath.Join(tmpDir, testFile), []byte("content"), 0644)
	require.NoError(t, err)

	// Run a command that depends on the working directory
	result := runner.RunWithDir(ctx, tmpDir, "/bin/sh", "-c", "ls")

	require.NoError(t, result.Error)
	assert.Contains(t, result.Stdout, testFile)
}

func TestRealRunner_Run_EnvironmentVariables(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	// Set a custom environment variable
	env := []string{"TEST_VAR=test-value-12345"}
	result := runner.RunWithEnv(ctx, env, "/bin/sh", "-c", "echo $TEST_VAR")

	require.NoError(t, result.Error)
	assert.Contains(t, result.Stdout, "test-value-12345")
}

func TestRealRunner_Run_Attached(t *testing.T) {
	runner := NewRealRunner()
	ctx := context.Background()

	// Test that RunAttached works with a simple echo command
	// This should print to the real stdout/stderr
	err := runner.RunAttached(ctx, "/bin/echo", "attached-mode-test")
	assert.NoError(t, err)
}

func TestFakeRunner_Recording(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	// Set up a default response
	runner.DefaultResponse = CommandResult{
		Stdout:   "default-stdout",
		ExitCode: 0,
	}

	// Run some commands
	_ = runner.Run(ctx, "echo", "test1")
	_ = runner.Run(ctx, "ls", "-la")
	_ = runner.RunWithInput(ctx, "input", "cat")

	// Verify commands were recorded
	require.Len(t, runner.Commands, 3)
	assert.Contains(t, runner.Commands[0], "echo test1")
	assert.Contains(t, runner.Commands[1], "ls -la")
	assert.Contains(t, runner.Commands[2], "cat")
	assert.Contains(t, runner.Commands[2], "input")

	// Test Reset
	runner.Reset()
	assert.Empty(t, runner.Commands)
	assert.Empty(t, runner.AttachedCommands)
}

func TestFakeRunner_ScriptedResponses(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	// Set up scripted responses
	runner.AddSuccess("echo hello", "hello-output")
	runner.AddError("false", 1, "command failed")
	runner.AddResponse("cat", CommandResult{
		Stdout:   "cat-output",
		Stderr:   "cat-stderr",
		ExitCode: 0,
	})

	// Test echo command
	result := runner.Run(ctx, "echo", "hello")
	assert.Equal(t, "hello-output", result.Stdout)
	assert.Equal(t, 0, result.ExitCode)

	// Test false command
	result = runner.Run(ctx, "false")
	assert.Equal(t, 1, result.ExitCode)
	assert.Contains(t, result.Stderr, "command failed")

	// Test cat command (matches by command name only)
	result = runner.Run(ctx, "cat", "file.txt")
	assert.Equal(t, "cat-output", result.Stdout)
}

func TestFakeRunner_OnCall(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	callCount := 0
	runner.OnCall = func(name string, args ...string) CommandResult {
		callCount++
		return CommandResult{
			Stdout:   "dynamic-" + name,
			ExitCode: 0,
		}
	}

	result := runner.Run(ctx, "echo", "test")
	assert.Equal(t, "dynamic-echo", result.Stdout)
	assert.Equal(t, 1, callCount)

	result = runner.Run(ctx, "ls")
	assert.Equal(t, "dynamic-ls", result.Stdout)
	assert.Equal(t, 2, callCount)
}

func TestFakeRunner_AttachedCommands(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	// Run some attached commands
	err := runner.RunAttached(ctx, "sudo", "ls")
	assert.NoError(t, err)

	runner.AttachedError = errors.New("attached failed")
	err = runner.RunAttached(ctx, "sudo", "cat", "file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "attached failed")

	// Verify commands were recorded
	require.Len(t, runner.AttachedCommands, 2)
	assert.Contains(t, runner.AttachedCommands[0], "sudo ls")
	assert.Contains(t, runner.AttachedCommands[1], "sudo cat file.txt")
}

func TestFakeRunner_LastCommand(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	assert.Empty(t, runner.LastCommand())

	_ = runner.Run(ctx, "echo", "first")
	assert.Equal(t, "echo first", runner.LastCommand())

	_ = runner.Run(ctx, "ls", "-la")
	assert.Equal(t, "ls -la", runner.LastCommand())

	runner.Reset()
	assert.Empty(t, runner.LastCommand())
}

func TestFakeRunner_HelperMethods(t *testing.T) {
	runner := NewFakeRunner()

	// Test AddSuccess
	runner.AddSuccess("echo", "success-output")
	result := runner.Run(context.Background(), "echo")
	assert.Equal(t, "success-output", result.Stdout)
	assert.Equal(t, 0, result.ExitCode)
	assert.NoError(t, result.Error)

	// Test AddError
	runner.AddError("false", 42, "error-output")
	result = runner.Run(context.Background(), "false")
	assert.Equal(t, 42, result.ExitCode)
	assert.Equal(t, "error-output", result.Stderr)
	assert.Error(t, result.Error)
}

func TestFakeRunner_RunWithDirAndEnv(t *testing.T) {
	runner := NewFakeRunner()
	ctx := context.Background()

	// These should log the dir/env but still work
	runner.DefaultResponse = CommandResult{
		Stdout:   "output",
		ExitCode: 0,
	}

	// RunWithDir records the command with dir annotation, then calls Run which records again
	// So we expect 2 command entries
	result := runner.RunWithDir(ctx, "/tmp", "ls", "-la")
	assert.Equal(t, "output", result.Stdout)
	// The first entry should have the dir annotation
	assert.Contains(t, runner.Commands[0], "dir: /tmp")
	// The second entry is from Run()
	assert.Equal(t, "ls -la", runner.Commands[1])

	runner.Reset()

	result = runner.RunWithEnv(ctx, []string{"VAR=value"}, "echo", "test")
	assert.Equal(t, "output", result.Stdout)
	assert.Contains(t, runner.Commands[0], "env: [VAR=value]")
	assert.Equal(t, "echo test", runner.Commands[1])
}
