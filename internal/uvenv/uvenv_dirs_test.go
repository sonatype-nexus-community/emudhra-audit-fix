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
	"testing"
)

// fakeRunner implements Runner for testing
type fakeRunner struct {
	responses map[string]CommandResult
	calls     []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		responses: make(map[string]CommandResult),
		calls:     []string{},
	}
}

func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) CommandResult {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)

	key := strings.Join(args, " ")
	if resp, ok := r.responses[key]; ok {
		return resp
	}
	return CommandResult{Stdout: "", ExitCode: 0}
}

func (r *fakeRunner) setResponse(args string, stdout string, err error) {
	r.responses[args] = CommandResult{
		Stdout:   stdout,
		Stderr:   "",
		ExitCode: 0,
		Error:    err,
	}
}

func (r *fakeRunner) setError(args string, exitCode int, errMsg string) {
	r.responses[args] = CommandResult{
		Stdout:   "",
		Stderr:   errMsg,
		ExitCode: exitCode,
		Error:    fmt.Errorf("%s", errMsg),
	}
}

// TestRead tests the Read function.
func TestRead(t *testing.T) {
	t.Run("calls uv with offline flags", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "/test/python", nil)

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		result, err := env.Read(ctx, "python", "dir")
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if result != "/test/python" {
			t.Errorf("expected /test/python, got %q", result)
		}

		// Verify the call included offline flags
		if len(runner.calls) == 0 {
			t.Fatal("no calls recorded")
		}
		call := runner.calls[0]
		if !strings.Contains(call, "--offline") {
			t.Error("expected --offline flag in call")
		}
		if !strings.Contains(call, "--no-config") {
			t.Error("expected --no-config flag in call")
		}
		if !strings.Contains(call, "--no-python-downloads") {
			t.Error("expected --no-python-downloads flag in call")
		}
		if !strings.Contains(call, "--cache-dir") {
			t.Error("expected --cache-dir flag in call")
		}
	})

	t.Run("returns error when uv binary not set", func(t *testing.T) {
		env := &Env{
			UV:      "",
			WorkDir: t.TempDir(),
			runner:  newFakeRunner(),
		}

		ctx := context.Background()
		_, err := env.Read(ctx, "python", "dir")
		if err == nil {
			t.Error("expected error when UV binary not set")
		}
	})

	t.Run("returns error on non-zero exit", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setError("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", 1, "command failed")

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		_, err := env.Read(ctx, "python", "dir")
		if err == nil {
			t.Error("expected error on non-zero exit")
		}
	})

	t.Run("trims whitespace from output", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "  /test/python  \n", nil)

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		result, err := env.Read(ctx, "python", "dir")
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if result != "/test/python" {
			t.Errorf("expected /test/python (trimmed), got %q", result)
		}
	})
}

// TestAbsoluteDir tests the AbsoluteDir function.
func TestAbsoluteDir(t *testing.T) {
	t.Run("returns absolute path unchanged", func(t *testing.T) {
		tmpDir := t.TempDir()
		env := &Env{WorkDir: tmpDir}

		result, err := env.AbsoluteDir("/absolute/path")
		if err != nil {
			t.Fatalf("AbsoluteDir failed: %v", err)
		}

		if result != "/absolute/path" {
			t.Errorf("expected /absolute/path, got %q", result)
		}
	})

	t.Run("resolves relative path against WorkDir", func(t *testing.T) {
		tmpDir := t.TempDir()
		env := &Env{WorkDir: tmpDir}

		result, err := env.AbsoluteDir("relative/path")
		if err != nil {
			t.Fatalf("AbsoluteDir failed: %v", err)
		}

		expected := filepath.Join(tmpDir, "relative", "path")
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("returns error for empty string", func(t *testing.T) {
		env := &Env{WorkDir: t.TempDir()}

		_, err := env.AbsoluteDir("")
		if err == nil {
			t.Error("expected error for empty string")
		}
	})

	t.Run("returns error for string with newline", func(t *testing.T) {
		env := &Env{WorkDir: t.TempDir()}

		_, err := env.AbsoluteDir("path\nwith\nnewline")
		if err == nil {
			t.Error("expected error for string with newline")
		}
	})

	t.Run("resolves symlinks for existing directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create real directory and symlink
		realDir := filepath.Join(tmpDir, "real")
		linkDir := filepath.Join(tmpDir, "link")
		if err := os.MkdirAll(realDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}

		env := &Env{WorkDir: tmpDir}

		result, err := env.AbsoluteDir(linkDir)
		if err != nil {
			t.Fatalf("AbsoluteDir failed: %v", err)
		}

		// Should resolve to the real directory (may differ due to symlinks in the path)
		// Just check that link is resolved
		if result == linkDir {
			t.Errorf("expected symlink to be resolved, got %q", result)
		}
	})
}

// TestEnvironmentDirs tests the EnvironmentDirs function.
func TestEnvironmentDirs(t *testing.T) {
	t.Run("queries uv for python and tool directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "/test/python", nil)
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" tool dir", "/test/tools", nil)

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		dirs, err := env.EnvironmentDirs(ctx)
		if err != nil {
			t.Fatalf("EnvironmentDirs failed: %v", err)
		}

		if dirs.Python != "/test/python" {
			t.Errorf("expected Python /test/python, got %q", dirs.Python)
		}
		if dirs.Tool != "/test/tools" {
			t.Errorf("expected Tool /test/tools, got %q", dirs.Tool)
		}
	})

	t.Run("applies environment variable overrides", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "/default/python", nil)
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" tool dir", "/default/tools", nil)

		env := &Env{
			UV:                uvPath,
			WorkDir:           tmpDir,
			runner:            runner,
			pythonDirOverride: "/override/python",
			toolDirOverride:   "/override/tools",
		}

		ctx := context.Background()
		dirs, err := env.EnvironmentDirs(ctx)
		if err != nil {
			t.Fatalf("EnvironmentDirs failed: %v", err)
		}

		if dirs.Python != "/override/python" {
			t.Errorf("expected Python /override/python, got %q", dirs.Python)
		}
		if dirs.Tool != "/override/tools" {
			t.Errorf("expected Tool /override/tools, got %q", dirs.Tool)
		}
	})

	t.Run("resolves relative override paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "/default/python", nil)
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" tool dir", "/default/tools", nil)

		env := &Env{
			UV:                uvPath,
			WorkDir:           tmpDir,
			runner:            runner,
			pythonDirOverride: "relative/python",
			toolDirOverride:   "relative/tools",
		}

		ctx := context.Background()
		dirs, err := env.EnvironmentDirs(ctx)
		if err != nil {
			t.Fatalf("EnvironmentDirs failed: %v", err)
		}

		// Relative paths should be resolved against WorkDir
		if dirs.Python != filepath.Join(tmpDir, "relative", "python") {
			t.Errorf("expected Python %q, got %q", filepath.Join(tmpDir, "relative", "python"), dirs.Python)
		}
		if dirs.Tool != filepath.Join(tmpDir, "relative", "tools") {
			t.Errorf("expected Tool %q, got %q", filepath.Join(tmpDir, "relative", "tools"), dirs.Tool)
		}
	})

	t.Run("handles discovery failure gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setError("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", 1, "failed")
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" tool dir", "/test/tools", nil)

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		dirs, err := env.EnvironmentDirs(ctx)
		if err != nil {
			t.Fatalf("EnvironmentDirs failed: %v", err)
		}

		// Should return empty Python dir on failure
		if dirs.Python != "" {
			t.Errorf("expected empty Python on failure, got %q", dirs.Python)
		}
		// Tool should still work
		if dirs.Tool != "/test/tools" {
			t.Errorf("expected Tool /test/tools, got %q", dirs.Tool)
		}
	})

	t.Run("rejects output with newlines", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir", "/test/python\n/other", nil)
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" tool dir", "/test/tools", nil)

		env := &Env{
			UV:      uvPath,
			WorkDir: tmpDir,
			runner:  runner,
		}

		ctx := context.Background()
		dirs, err := env.EnvironmentDirs(ctx)
		if err != nil {
			t.Fatalf("EnvironmentDirs failed: %v", err)
		}

		// Should return empty on newline in output
		if dirs.Python != "" {
			t.Errorf("expected empty Python on newline, got %q", dirs.Python)
		}
	})
}
