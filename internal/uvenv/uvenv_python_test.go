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
	"os"
	"path/filepath"
	"testing"
)

// TestManagedMinor tests the ManagedMinor function.
func TestManagedMinor(t *testing.T) {
	tests := []struct {
		name        string
		dirPath     string
		fullVersion string
		impl        string
		want        string
	}{
		{
			name:        "valid cpython 3.12",
			dirPath:     "/home/.local/share/uv/python/cpython-3.12.0-macos-aarch64-none",
			fullVersion: "3.12.0",
			impl:        "cpython",
			want:        "3.12",
		},
		{
			name:        "valid cpython 3.13",
			dirPath:     "/home/.local/share/uv/python/cpython-3.13.2-linux-x86_64-gnu",
			fullVersion: "3.13.2",
			impl:        "cpython",
			want:        "3.13",
		},
		{
			name:        "valid cpython two-digit minor",
			dirPath:     "/home/.local/share/uv/python/cpython-3.10.15-macos-aarch64-none",
			fullVersion: "3.10.15",
			impl:        "cpython",
			want:        "3.10",
		},
		{
			name:        "rejects non-cpython",
			dirPath:     "/home/.local/share/uv/python/pypy-3.12.0-macos-aarch64-none",
			fullVersion: "3.12.0",
			impl:        "pypy",
			want:        "",
		},
		{
			name:        "rejects free-threaded variant",
			dirPath:     "/home/.local/share/uv/python/cpython-3.13.0+freethreaded-macos-aarch64-none",
			fullVersion: "3.13.0+freethreaded",
			impl:        "cpython",
			want:        "",
		},
		{
			name:        "rejects wrong version prefix",
			dirPath:     "/home/.local/share/uv/python/cpython-3.12.0-macos-aarch64-none",
			fullVersion: "3.13.0",
			impl:        "cpython",
			want:        "",
		},
		{
			name:        "rejects non-cpython directory",
			dirPath:     "/home/.local/share/uv/python/python-3.12.0",
			fullVersion: "3.12.0",
			impl:        "cpython",
			want:        "",
		},
		{
			name:        "rejects a cpython-named directory outside uv's Python directory",
			dirPath:     "/opt/other/cpython-3.12.0-macos-aarch64-none",
			fullVersion: "3.12.0",
			impl:        "cpython",
			want:        "",
		},
		{
			name:        "rejects a sibling whose name merely starts with the Python directory's",
			dirPath:     "/home/.local/share/uv/python2/cpython-3.12.0-macos-aarch64-none",
			fullVersion: "3.12.0",
			impl:        "cpython",
			want:        "",
		},
		{
			name:        "rejects empty version",
			dirPath:     "/home/.local/share/uv/python/cpython--macos-aarch64-none",
			fullVersion: "",
			impl:        "cpython",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (&Env{PythonDir: "/home/.local/share/uv/python"}).ManagedMinor(tt.dirPath, tt.fullVersion, tt.impl)
			if got != tt.want {
				t.Errorf("ManagedMinor() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPythonLatest tests the PythonLatest function.
func TestPythonLatest(t *testing.T) {
	t.Run("finds latest patch version", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python list --only-downloads --managed-python cpython@3.12",
			"cpython-3.12.0-macos-aarch64-none <download available>\ncpython-3.12.1-macos-aarch64-none <download available>\ncpython-3.12.5-macos-aarch64-none <download available>\n",
			nil)

		env := &Env{
			UV:        uvPath,
			PythonDir: filepath.Join(tmpDir, "python"),
			WorkDir:   tmpDir,
			runner:    runner,
		}

		ctx := context.Background()
		got, err := env.PythonLatest(ctx, tmpDir+"/python/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if err != nil {
			t.Fatalf("PythonLatest failed: %v", err)
		}

		if got != "3.12.5" {
			t.Errorf("expected 3.12.5, got %q", got)
		}
	})

	t.Run("matches suffix when extracting version", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python list --only-downloads --managed-python cpython@3.12",
			"cpython-3.12.0-macos-aarch64-none <download available>\ncpython-3.12.5-linux-x86_64-gnu <download available>\ncpython-3.12.3-macos-aarch64-none <download available>\n",
			nil)

		env := &Env{
			UV:        uvPath,
			PythonDir: filepath.Join(tmpDir, "python"),
			WorkDir:   tmpDir,
			runner:    runner,
		}

		ctx := context.Background()
		// Query with macos suffix, should only match macos versions
		got, err := env.PythonLatest(ctx, tmpDir+"/python/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if err != nil {
			t.Fatalf("PythonLatest failed: %v", err)
		}

		// Should be 3.12.3 (latest macos), not 3.12.5 (linux)
		if got != "3.12.3" {
			t.Errorf("expected 3.12.3, got %q", got)
		}
	})

	// uv_python_latest writes "unknown" only when `uv python list` FAILS. When it succeeds but
	// nothing in the catalogue matches this interpreter family, the answer is the empty string
	// ("uv reports no downloadable patch for this interpreter family"), which the audit words
	// differently from "the catalogue could not be read".
	t.Run("a catalogue that lists nothing for this family is empty, not unknown", func(t *testing.T) {
		tmpDir := t.TempDir()
		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python list --only-downloads --managed-python cpython@3.12",
			"cpython-3.12.5-linux-x86_64-gnu <download available>\ncpython-3.13.1-macos-aarch64-none <download available>\n", nil)
		env := &Env{UV: filepath.Join(tmpDir, "bin", "uv"), PythonDir: filepath.Join(tmpDir, "python"), WorkDir: tmpDir, runner: runner}

		got, err := env.PythonLatest(context.Background(), tmpDir+"/python/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if err != nil {
			t.Fatalf("PythonLatest failed: %v", err)
		}
		if got != "" {
			t.Errorf("a readable catalogue with no matching entry must give \"\", got %q", got)
		}
	})

	t.Run("an empty catalogue is empty, not unknown", func(t *testing.T) {
		tmpDir := t.TempDir()
		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python list --only-downloads --managed-python cpython@3.12", "", nil)
		env := &Env{UV: filepath.Join(tmpDir, "bin", "uv"), PythonDir: filepath.Join(tmpDir, "python"), WorkDir: tmpDir, runner: runner}
		got, _ := env.PythonLatest(context.Background(), tmpDir+"/python/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if got != "" {
			t.Errorf("an empty but successful listing must give \"\", got %q", got)
		}
	})

	t.Run("returns unknown on query failure", func(t *testing.T) {
		tmpDir := t.TempDir()
		uvPath := filepath.Join(tmpDir, "bin", "uv")

		runner := newFakeRunner()
		runner.setError("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python list --only-downloads --managed-python cpython@3.12", 1, "failed")

		env := &Env{
			UV:        uvPath,
			PythonDir: filepath.Join(tmpDir, "python"),
			WorkDir:   tmpDir,
			runner:    runner,
		}

		ctx := context.Background()
		got, err := env.PythonLatest(ctx, tmpDir+"/python/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if err != nil {
			t.Fatalf("PythonLatest failed: %v", err)
		}

		if got != "unknown" {
			t.Errorf("expected unknown on failure, got %q", got)
		}
	})

	t.Run("rejects non-managed install", func(t *testing.T) {
		env := &Env{
			PythonDir: t.TempDir(),
		}

		ctx := context.Background()
		_, err := env.PythonLatest(ctx, "/pypy-3.12.0", "3.12.0")
		if err == nil {
			t.Error("expected error for non-cpython install")
		}
	})
}

// TestPythonNewestInstalled tests the PythonNewestInstalled function.
func TestPythonNewestInstalled(t *testing.T) {
	t.Run("finds newest installed patch", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")

		// Create multiple Python installations
		versions := []string{"cpython-3.12.0-macos-aarch64-none", "cpython-3.12.3-macos-aarch64-none", "cpython-3.12.5-macos-aarch64-none"}
		for _, v := range versions {
			dir := filepath.Join(pythonDir, v, "bin")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			// Create python3 executable marker
			if err := os.WriteFile(filepath.Join(dir, "python3"), []byte("#!/bin/sh"), 0755); err != nil {
				t.Fatal(err)
			}
		}

		env := &Env{
			PythonDir: pythonDir,
		}

		ctx := context.Background()
		got, err := env.PythonNewestInstalled(ctx, filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none"), "3.12.0")
		if err != nil {
			t.Fatalf("PythonNewestInstalled failed: %v", err)
		}

		if got != "3.12.5" {
			t.Errorf("expected 3.12.5, got %q", got)
		}
	})

	t.Run("returns provided version when no installations found", func(t *testing.T) {
		tmpDir := t.TempDir()
		env := &Env{
			PythonDir: tmpDir,
		}

		ctx := context.Background()
		got, err := env.PythonNewestInstalled(ctx, tmpDir+"/cpython-3.12.0-macos-aarch64-none", "3.12.0")
		if err != nil {
			t.Fatalf("PythonNewestInstalled failed: %v", err)
		}

		if got != "3.12.0" {
			t.Errorf("expected 3.12.0 (fallback), got %q", got)
		}
	})

	t.Run("only considers directories with python3 executable", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")

		// Create installation with executable
		dir1 := filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none", "bin")
		if err := os.MkdirAll(dir1, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir1, "python3"), []byte("#!/bin/sh"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create installation WITHOUT executable
		dir2 := filepath.Join(pythonDir, "cpython-3.12.5-macos-aarch64-none", "bin")
		if err := os.MkdirAll(dir2, 0755); err != nil {
			t.Fatal(err)
		}
		// No python3 file

		env := &Env{
			PythonDir: pythonDir,
		}

		ctx := context.Background()
		got, err := env.PythonNewestInstalled(ctx, filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none"), "3.12.0")
		if err != nil {
			t.Fatalf("PythonNewestInstalled failed: %v", err)
		}

		// Should return 3.12.0 (only one with executable)
		if got != "3.12.0" {
			t.Errorf("expected 3.12.0, got %q", got)
		}
	})

	t.Run("matches suffix for platform-specific installs", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")

		// Create installations with different suffixes
		for _, v := range []string{"cpython-3.12.0-macos-aarch64-none", "cpython-3.12.5-linux-x86_64-gnu"} {
			dir := filepath.Join(pythonDir, v, "bin")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "python3"), []byte("#!/bin/sh"), 0755); err != nil {
				t.Fatal(err)
			}
		}

		env := &Env{
			PythonDir: pythonDir,
		}

		ctx := context.Background()
		// Query with macos suffix, should only match macos
		got, err := env.PythonNewestInstalled(ctx, filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none"), "3.12.0")
		if err != nil {
			t.Fatalf("PythonNewestInstalled failed: %v", err)
		}

		// Should return 3.12.0 (only macos version)
		if got != "3.12.0" {
			t.Errorf("expected 3.12.0, got %q", got)
		}
	})
}

// TestPythonIsSelected tests the PythonIsSelected function.
func TestPythonIsSelected(t *testing.T) {
	// binDirAnswer is what `uv python dir --bin` prints. uv's launcher directory is not inside
	// the Python directory (it is ~/.local/bin unless UV_PYTHON_BIN_DIR says otherwise).
	setup := func(t *testing.T, binExists bool) (env *Env, installDir, binDir string) {
		t.Helper()
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")
		binDir = filepath.Join(tmpDir, "launchers")
		installDir = filepath.Join(pythonDir, "cpython-3.12.3-macos-aarch64-none")
		if err := os.MkdirAll(filepath.Join(installDir, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installDir, "bin", "python3"), []byte("#!/bin/sh"), 0755); err != nil {
			t.Fatal(err)
		}
		if binExists {
			if err := os.MkdirAll(binDir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		runner := newFakeRunner()
		runner.setResponse("--offline --no-config --no-python-downloads --cache-dir "+filepath.Join(tmpDir, "uv-cache")+" python dir --bin", binDir+"\n", nil)
		env = &Env{UV: filepath.Join(tmpDir, "uv"), PythonDir: pythonDir, WorkDir: tmpDir, runner: runner}
		return env, installDir, binDir
	}

	t.Run("true when the minor alias points at this installation", func(t *testing.T) {
		env, installDir, _ := setup(t, true)
		preferred := filepath.Join(env.PythonDir, "cpython-3.12-macos-aarch64-none")
		if err := os.Symlink(installDir, preferred); err != nil {
			t.Fatal(err)
		}
		if !env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("expected true for the preferred installation")
		}
	})

	t.Run("true when a launcher in uv's bin directory points into this installation", func(t *testing.T) {
		env, installDir, binDir := setup(t, true)
		if err := os.Symlink(filepath.Join(installDir, "bin", "python3"), filepath.Join(binDir, "python3")); err != nil {
			t.Fatal(err)
		}
		if !env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("expected true when a launcher selects this installation")
		}
	})

	t.Run("a launcher in a bin directory INSIDE the python directory does not count", func(t *testing.T) {
		// This is where the code used to look. uv does not put launchers there.
		env, installDir, _ := setup(t, true)
		wrong := filepath.Join(env.PythonDir, "bin")
		if err := os.MkdirAll(wrong, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(installDir, "bin", "python3"), filepath.Join(wrong, "python3")); err != nil {
			t.Fatal(err)
		}
		if env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("a link in <pythondir>/bin is not one of uv's launchers")
		}
	})

	t.Run("false when nothing selects it", func(t *testing.T) {
		env, installDir, binDir := setup(t, true)
		other := filepath.Join(env.PythonDir, "cpython-3.12.9-macos-aarch64-none", "bin")
		if err := os.MkdirAll(other, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, "python3"), []byte("#!/bin/sh"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(other, "python3"), filepath.Join(binDir, "python3")); err != nil {
			t.Fatal(err)
		}
		if env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("the launcher selects a different patch, so this one is not selected")
		}
	})

	// `bindir=$(uv_bin_dir python) || return 0`: if the launcher directory cannot be found the
	// script cannot rule the install out, so it assumes the older patch IS in use.
	t.Run("true when uv's bin directory cannot be found (conservative)", func(t *testing.T) {
		env, installDir, _ := setup(t, false) // the directory does not exist
		if !env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("an unknown launcher directory must be treated as selected")
		}
	})

	t.Run("true when uv cannot answer at all (conservative)", func(t *testing.T) {
		env, installDir, _ := setup(t, true)
		env.runner = newFakeRunner() // no scripted answer: the command fails
		if !env.PythonIsSelected(context.Background(), installDir, "3.12.3") {
			t.Error("a failing uv must be treated as selected")
		}
	})

	t.Run("false for a non-managed directory", func(t *testing.T) {
		env, _, _ := setup(t, true)
		if env.PythonIsSelected(context.Background(), "/opt/homebrew/Cellar/python", "3.12.3") {
			t.Error("only managed installs can be selected")
		}
	})
}

// TestPythonImports tests the PythonImports function.
func TestPythonImports(t *testing.T) {
	t.Run("lists cpython directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		pythonDir := filepath.Join(tmpDir, "python")

		// Create some installations
		for _, name := range []string{"cpython-3.12.0-macos-aarch64-none", "cpython-3.13.0-macos-aarch64-none"} {
			if err := os.MkdirAll(filepath.Join(pythonDir, name), 0755); err != nil {
				t.Fatal(err)
			}
		}
		// Create a non-cpython directory (should be ignored)
		if err := os.MkdirAll(filepath.Join(pythonDir, "other"), 0755); err != nil {
			t.Fatal(err)
		}

		env := &Env{
			PythonDir: pythonDir,
		}

		ctx := context.Background()
		imports, err := env.PythonImports(ctx)
		if err != nil {
			t.Fatalf("PythonImports failed: %v", err)
		}

		if len(imports) != 2 {
			t.Errorf("expected 2 imports, got %d", len(imports))
		}

		// Should be sorted
		expected := []string{
			filepath.Join(pythonDir, "cpython-3.12.0-macos-aarch64-none"),
			filepath.Join(pythonDir, "cpython-3.13.0-macos-aarch64-none"),
		}
		for i, imp := range imports {
			if imp != expected[i] {
				t.Errorf("imports[%d] = %q, want %q", i, imp, expected[i])
			}
		}
	})

	t.Run("returns empty when PythonDir not set", func(t *testing.T) {
		env := &Env{PythonDir: ""}

		ctx := context.Background()
		imports, err := env.PythonImports(ctx)
		if err != nil {
			t.Fatalf("PythonImports failed: %v", err)
		}

		if len(imports) != 0 {
			t.Errorf("expected 0 imports, got %d", len(imports))
		}
	})

	t.Run("returns empty when directory does not exist", func(t *testing.T) {
		env := &Env{PythonDir: "/nonexistent"}

		ctx := context.Background()
		imports, err := env.PythonImports(ctx)
		if err != nil {
			t.Fatalf("PythonImports failed: %v", err)
		}

		if len(imports) != 0 {
			t.Errorf("expected 0 imports, got %d", len(imports))
		}
	})
}

// BinDir is uv_bin_dir: what `uv KIND dir --bin` reports, made absolute, required to exist, and
// resolved. The directory is not inside the Python or tool directory.
func TestBinDir(t *testing.T) {
	cacheArgs := func(tmp string) string {
		return "--offline --no-config --no-python-downloads --cache-dir " + filepath.Join(tmp, "uv-cache") + " "
	}
	t.Run("asks uv for the right kind and returns the resolved directory", func(t *testing.T) {
		tmp := t.TempDir()
		real := filepath.Join(tmp, "real-bin")
		link := filepath.Join(tmp, "link-bin")
		if err := os.MkdirAll(real, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		runner := newFakeRunner()
		runner.setResponse(cacheArgs(tmp)+"python dir --bin", link+"\n", nil)
		runner.setResponse(cacheArgs(tmp)+"tool dir --bin", filepath.Join(tmp, "tool-bin")+"\n", nil)
		if err := os.MkdirAll(filepath.Join(tmp, "tool-bin"), 0755); err != nil {
			t.Fatal(err)
		}
		env := &Env{UV: filepath.Join(tmp, "uv"), WorkDir: tmp, runner: runner}

		got, err := env.BinDir(context.Background(), "python")
		if err != nil {
			t.Fatal(err)
		}
		want, _ := filepath.EvalSymlinks(real)
		if got != want {
			t.Errorf("python: want the resolved %q, got %q (cd -P)", want, got)
		}
		gotTool, err := env.BinDir(context.Background(), "tool")
		if err != nil {
			t.Fatal(err)
		}
		wantTool, _ := filepath.EvalSymlinks(filepath.Join(tmp, "tool-bin"))
		if gotTool != wantTool {
			t.Errorf("tool: got %q, want %q: the kind must reach uv", gotTool, wantTool)
		}
	})

	t.Run("a relative answer is resolved against uv's working directory", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.MkdirAll(filepath.Join(tmp, "rel", "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		runner := newFakeRunner()
		runner.setResponse(cacheArgs(tmp)+"python dir --bin", "rel/bin\n", nil)
		env := &Env{UV: filepath.Join(tmp, "uv"), WorkDir: tmp, runner: runner}
		got, err := env.BinDir(context.Background(), "python")
		if err != nil {
			t.Fatal(err)
		}
		want, _ := filepath.EvalSymlinks(filepath.Join(tmp, "rel", "bin"))
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("a directory that does not exist is refused", func(t *testing.T) {
		tmp := t.TempDir()
		runner := newFakeRunner()
		runner.setResponse(cacheArgs(tmp)+"python dir --bin", filepath.Join(tmp, "missing")+"\n", nil)
		env := &Env{UV: filepath.Join(tmp, "uv"), WorkDir: tmp, runner: runner}
		if _, err := env.BinDir(context.Background(), "python"); err == nil {
			t.Error("uv_bin_dir fails when the directory is not there")
		}
	})

	t.Run("a file is not a directory", func(t *testing.T) {
		tmp := t.TempDir()
		f := filepath.Join(tmp, "afile")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		runner := newFakeRunner()
		runner.setResponse(cacheArgs(tmp)+"python dir --bin", f+"\n", nil)
		env := &Env{UV: filepath.Join(tmp, "uv"), WorkDir: tmp, runner: runner}
		if _, err := env.BinDir(context.Background(), "python"); err == nil {
			t.Error("a file must be refused")
		}
	})

	t.Run("uv failing is an error", func(t *testing.T) {
		tmp := t.TempDir()
		runner := newFakeRunner()
		runner.setError(cacheArgs(tmp)+"python dir --bin", 1, "boom")
		env := &Env{UV: filepath.Join(tmp, "uv"), WorkDir: tmp, runner: runner}
		if _, err := env.BinDir(context.Background(), "python"); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestManagedMinorNeedsAKnownPythonDirectory(t *testing.T) {
	if got := (&Env{}).ManagedMinor("/cpython-3.12.0-x/cpython-3.12.0-macos", "3.12.0", "cpython"); got != "" {
		t.Errorf("without a Python directory nothing is managed, got %q", got)
	}
}

// uv may report its Python directory through a symlink while the interpreter's own base prefix
// is physical (macOS /var -> /private/var).
func TestManagedMinorAcceptsAPhysicalPathUnderASymlinkedPythonDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "cpython-3.12.4-macos-aarch64-none"), 0o755); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(root, "via")
	if err := os.Symlink(real, via); err != nil {
		t.Fatal(err)
	}
	e := &Env{PythonDir: via}
	if got := e.ManagedMinor(filepath.Join(real, "cpython-3.12.4-macos-aarch64-none"), "3.12.4", "cpython"); got != "3.12" {
		t.Errorf("got %q", got)
	}
}
