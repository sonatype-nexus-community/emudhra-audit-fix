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

package uvenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Read executes the uv binary with the given arguments in offline mode.
// It runs the uv binary with --offline --no-config --no-python-downloads,
// and a cache directory under TempDir, with a 15-second timeout.
// Ports uv_read (lines 650-653).
func (e *Env) Read(ctx context.Context, args ...string) (string, error) {
	if e.UV == "" {
		return "", fmt.Errorf("uv binary not set")
	}

	// Create cache directory under TempDir
	cacheDir := filepath.Join(e.WorkDir, "uv-cache")

	// Build command arguments
	cmdArgs := []string{
		"--offline",
		"--no-config",
		"--no-python-downloads",
		"--cache-dir", cacheDir,
	}
	cmdArgs = append(cmdArgs, args...)

	// Create a context with 15-second timeout
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Run through the runner (env.Run from kinds.Env).
	result := e.runner.Run(ctx, e.UV, cmdArgs...)
	if result.Error != nil {
		return "", result.Error
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("uv command failed with exit code %d: %s", result.ExitCode, result.Stderr)
	}

	return strings.TrimSpace(result.Stdout), nil
}

// AbsoluteDir returns the absolute path for a directory reported by uv,
// resolving relative paths against uv's working directory.
// Ports uv_absolute_dir (lines 656-662).
func (e *Env) AbsoluteDir(dir string) (string, error) {
	if dir == "" || strings.Contains(dir, "\n") {
		return "", fmt.Errorf("invalid directory: empty or contains newline")
	}

	// Get the working directory for resolution
	root := e.WorkDir
	if root == "" {
		root, _ = os.Getwd()
	}

	// Ensure root is absolute
	if !filepath.IsAbs(root) {
		root = filepath.Join("/", root)
	}

	// Resolve relative path against root
	var result string
	if filepath.IsAbs(dir) {
		result = dir
	} else {
		result = filepath.Join(root, dir)
	}

	// Clean and return
	result = filepath.Clean(result)

	// If the directory exists, resolve symlinks
	if info, err := os.Stat(result); err == nil && info.IsDir() {
		if resolved, err := filepath.EvalSymlinks(result); err == nil {
			return resolved, nil
		}
	}

	return result, nil
}

// Dirs holds the discovered directory paths for uv's Python and tool environments.
type Dirs struct {
	// Python is the path to UV_PYTHON_INSTALL_DIR (from "uv python dir").
	Python string

	// Tool is the path to UV_TOOL_DIR (from "uv tool dir").
	Tool string

	// WorkDir is the working directory for uv commands.
	WorkDir string
}

// EnvironmentDirs queries uv for its Python and tool directories, then returns them.
// It runs "uv python dir" and "uv tool dir" through Read, applies environment variable
// overrides (UV_PYTHON_INSTALL_DIR, UV_TOOL_DIR), and resolves relative paths against
// uv's working directory. Ports uv_environment_dirs (lines 664-699).
func (e *Env) EnvironmentDirs(ctx context.Context) (*Dirs, error) {
	dirs := &Dirs{
		WorkDir: e.WorkDir,
	}

	// Query uv for python dir
	pythonDir, err := e.Read(ctx, "python", "dir")
	if err == nil && pythonDir != "" && !strings.Contains(pythonDir, "\n") {
		// Apply UV_PYTHON_INSTALL_DIR override if set
		if e.pythonDirOverride != "" {
			pythonDir = e.pythonDirOverride
		}
		// Resolve to absolute path
		if dirs.Python, err = e.AbsoluteDir(pythonDir); err != nil {
			dirs.Python = pythonDir
		}
	} else if err != nil {
		// Discovery failed but not fatal - report as empty
		dirs.Python = ""
	}

	// Query uv for tool dir
	toolDir, err := e.Read(ctx, "tool", "dir")
	if err == nil && toolDir != "" && !strings.Contains(toolDir, "\n") {
		// Apply UV_TOOL_DIR override if set
		if e.toolDirOverride != "" {
			toolDir = e.toolDirOverride
		}
		// Resolve to absolute path
		if dirs.Tool, err = e.AbsoluteDir(toolDir); err != nil {
			dirs.Tool = toolDir
		}
	} else if err != nil {
		// Discovery failed but not fatal - report as empty
		dirs.Tool = ""
	}

	return dirs, nil
}

// BinDir ports uv_bin_dir: the directory uv puts executables for kind ("python" or "tool")
// into, which uv itself reports with `uv KIND dir --bin`. It is NOT inside the Python or tool
// directory (it is ~/.local/bin unless UV_PYTHON_BIN_DIR or UV_TOOL_BIN_DIR says otherwise),
// and it must exist: the script fails rather than guess.
func (e *Env) BinDir(ctx context.Context, kind string) (string, error) {
	out, err := e.Read(ctx, kind, "dir", "--bin")
	if err != nil {
		return "", err
	}
	dir, err := e.AbsoluteDir(out)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("uv's %s executable directory %s does not exist", kind, dir)
	}
	return filepath.EvalSymlinks(dir)
}
