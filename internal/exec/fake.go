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
	"fmt"
	"strings"
	"time"
)

// FakeRunner is a test implementation that records commands and returns scripted output.
type FakeRunner struct {
	// Commands is a record of all commands executed (for verification in tests).
	Commands []string

	// Responses maps command names to their scripted outputs.
	// Key is "name arg1 arg2..." (simple matching) or just the command name.
	// The script returns the first matching key.
	Responses map[string]CommandResult

	// DefaultResponse is returned when no scripted response matches.
	DefaultResponse CommandResult

	// OnCall is an optional callback invoked for each command (for dynamic responses).
	OnCall func(name string, args ...string) CommandResult

	// AttachedCommands records commands run with RunAttached.
	AttachedCommands []string

	// AttachedError is the error to return from RunAttached.
	AttachedError error
}

// NewFakeRunner creates a new FakeRunner with empty command history.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		Commands:         make([]string, 0),
		Responses:        make(map[string]CommandResult),
		AttachedCommands: make([]string, 0),
	}
}

// Run records the command and returns a scripted response.
func (f *FakeRunner) Run(ctx context.Context, name string, args ...string) CommandResult {
	// Record command
	cmdStr := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	f.Commands = append(f.Commands, cmdStr)

	// Check OnCall callback first
	if f.OnCall != nil {
		return f.OnCall(name, args...)
	}

	// Try full command match
	key := cmdStr
	if result, ok := f.Responses[key]; ok {
		return result
	}

	// Try command name only
	if result, ok := f.Responses[name]; ok {
		return result
	}

	// Return default
	return f.DefaultResponse
}

// RunWithInput records the command and returns a scripted response (input is logged but not used in matching).
func (f *FakeRunner) RunWithInput(ctx context.Context, input string, name string, args ...string) CommandResult {
	// Record command with input marker
	cmdStr := fmt.Sprintf("%s %s (input: %q)", name, strings.Join(args, " "), input)
	f.Commands = append(f.Commands, cmdStr)

	// Check OnCall callback first
	if f.OnCall != nil {
		return f.OnCall(name, args...)
	}

	// Try to match as regular command
	key := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	if result, ok := f.Responses[key]; ok {
		return result
	}

	if result, ok := f.Responses[name]; ok {
		return result
	}

	return f.DefaultResponse
}

// RunWithTimeout records the command and returns a scripted response (timeout is ignored in fake).
func (f *FakeRunner) RunWithTimeout(timeout time.Duration, name string, args ...string) CommandResult {
	return f.Run(context.Background(), name, args...)
}

// RunWithDir records the command and returns a scripted response (dir is logged but not used in matching).
func (f *FakeRunner) RunWithDir(ctx context.Context, dir string, name string, args ...string) CommandResult {
	cmdStr := fmt.Sprintf("%s %s (dir: %s)", name, strings.Join(args, " "), dir)
	f.Commands = append(f.Commands, cmdStr)
	return f.Run(ctx, name, args...)
}

// RunWithEnv records the command and returns a scripted response (env is logged but not used in matching).
func (f *FakeRunner) RunWithEnv(ctx context.Context, env []string, name string, args ...string) CommandResult {
	cmdStr := fmt.Sprintf("%s %s (env: %v)", name, strings.Join(args, " "), env)
	f.Commands = append(f.Commands, cmdStr)
	return f.Run(ctx, name, args...)
}

// RunAttached records the command and returns the scripted error (or nil).
func (f *FakeRunner) RunAttached(ctx context.Context, name string, args ...string) error {
	cmdStr := fmt.Sprintf("%s %s (attached)", name, strings.Join(args, " "))
	f.AttachedCommands = append(f.AttachedCommands, cmdStr)
	return f.AttachedError
}

// AddResponse adds a scripted response for a command.
func (f *FakeRunner) AddResponse(cmd string, result CommandResult) {
	f.Responses[cmd] = result
}

// AddSuccess adds a successful response for a command.
func (f *FakeRunner) AddSuccess(cmd, stdout string) {
	f.AddResponse(cmd, CommandResult{
		Stdout:   stdout,
		ExitCode: 0,
	})
}

// AddError adds an error response for a command.
func (f *FakeRunner) AddError(cmd string, exitCode int, stderr string) {
	f.AddResponse(cmd, CommandResult{
		Stderr:   stderr,
		ExitCode: exitCode,
		Error:    fmt.Errorf("exit code %d", exitCode),
	})
}

// LastCommand returns the last executed command (empty string if none).
func (f *FakeRunner) LastCommand() string {
	if len(f.Commands) == 0 {
		return ""
	}
	return f.Commands[len(f.Commands)-1]
}

// Reset clears the command history (preserves responses).
func (f *FakeRunner) Reset() {
	f.Commands = make([]string, 0)
	f.AttachedCommands = make([]string, 0)
}
