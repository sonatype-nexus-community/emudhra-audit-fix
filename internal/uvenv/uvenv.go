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

// Package uvenv holds what the uv, uvpython and uvtools Kinds share: finding uv, asking it where
// its directories are, judging which Python installs it manages, and the link, backup and
// restore helpers that make an upgrade reversible. It ports the uv_* functions of the legacy
// script.
//
//   - Discovery: FindUV, NewEnv, Env.Read (uv is always run offline with a private cache),
//     Env.EnvironmentDirs, Env.BinDir, Env.AbsoluteDir.
//   - Managed Pythons: Env.ManagedMinor, Env.PythonLatest, Env.PythonNewestInstalled,
//     Env.PythonIsSelected.
//   - Links and backups: UVLinkMatches, UVSaveLinks, UVRestoreLinks, UVPrepareBackups,
//     UVSavePythonInstalls, UVRestorePythonInstalls, UVRestoreTool, UVToolEntrypointsSafe, CopyTree.
//   - Names and devices: ToolNameSafe, UVStorageDevice.
package uvenv

import (
	"context"
	"path/filepath"
	"syscall"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
)

// Runner is an interface for executing commands (subset of exec.Runner).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) CommandResult
}

// CommandResult holds the result of a command execution (subset of exec.CommandResult).
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
}

// Env holds the uv binary path and environment variables for uvenv operations.
type Env struct {
	// UV is the path to the uv binary (resolved, absolute).
	UV string

	// PythonDir is UV_PYTHON_INSTALL_DIR (or the default $HOME/.local/share/uv/python).
	PythonDir string

	// ToolDir is UV_TOOL_DIR (or the default $HOME/.local/share/uv/tools).
	ToolDir string

	// WorkDir is the working directory for uv commands.
	WorkDir string

	// runner is the command runner (must be set via NewEnvWithRunner or tests).
	runner Runner

	// pythonDirOverride is UV_PYTHON_INSTALL_DIR from environment (can be relative).
	pythonDirOverride string

	// toolDirOverride is UV_TOOL_DIR from environment (can be relative).
	toolDirOverride string
}

// NewEnv creates a uvenv.Env from a kinds.Env and a uv binary path.
// It reads UV_PYTHON_INSTALL_DIR and UV_TOOL_DIR from the environment,
// defaulting to $HOME/.local/share/uv/python and $HOME/.local/share/uv/tools.
// The runner is adapted from kinds.Env.Run.
func NewEnv(env *kinds.Env, uvBinary string) *Env {
	home := env.Home()

	pythonDirOverride := env.Getenv("UV_PYTHON_INSTALL_DIR")
	pythonDirDefault := filepath.Join(home, ".local", "share", "uv", "python")
	pythonDir := pythonDirDefault
	if pythonDirOverride != "" {
		pythonDir = pythonDirOverride
	}

	toolDirOverride := env.Getenv("UV_TOOL_DIR")
	toolDirDefault := filepath.Join(home, ".local", "share", "uv", "tools")
	toolDir := toolDirDefault
	if toolDirOverride != "" {
		toolDir = toolDirOverride
	}

	return &Env{
		UV:                discover.Resolve(uvBinary),
		PythonDir:         pythonDir,
		ToolDir:           toolDir,
		WorkDir:           home,
		runner:            &runnerAdapter{env.Run},
		pythonDirOverride: pythonDirOverride,
		toolDirOverride:   toolDirOverride,
	}
}

// runnerAdapter adapts kinds.Env.Run (exec.Runner) to uvenv.Runner.
type runnerAdapter struct {
	run interface {
		Run(ctx context.Context, name string, args ...string) exec.CommandResult
	}
}

func (r *runnerAdapter) Run(ctx context.Context, name string, args ...string) CommandResult {
	result := r.run.Run(ctx, name, args...)
	return CommandResult{
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
		Error:    result.Error,
	}
}

// StorageDeviceFunc is the function used to get device IDs.
// It can be overridden in tests to simulate cross-device scenarios.
var StorageDeviceFunc = func(path string) int64 {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return -1
	}
	return int64(stat.Dev)
}

// UVStorageDevice returns the device number for a path (for cross-device checks).
// Ports uv_storage_device (lines 2812-2816).
// Returns -1 on error.
func UVStorageDevice(path string) int64 {
	return StorageDeviceFunc(path)
}

// ToolNameSafe ports uv_tool_name_safe: a tool name is safe to use as a directory name and in
// uv commands when it is non-empty, made only of letters, digits, '.', '_' and '-', and does not
// start with '-' or '.'.
func ToolNameSafe(name string) bool {
	if name == "" || name[0] == '-' || name[0] == '.' {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// FindUV locates the uv binary as uv_environment_dirs does: the one on PATH, else
// $HOME/.local/bin/uv, else $HOME/.cargo/bin/uv. It returns "" when there is none.
func FindUV(env *kinds.Env) string {
	if p := discover.Lookup("uv", env.Path()); p != "" {
		return p
	}
	for _, c := range []string{
		filepath.Join(env.Home(), ".local", "bin", "uv"),
		filepath.Join(env.Home(), ".cargo", "bin", "uv"),
	} {
		if discover.IsExecutable(c) {
			return c
		}
	}
	return ""
}
