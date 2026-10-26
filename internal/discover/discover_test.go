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

package discover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhereFrom(t *testing.T) {
	tests := []struct {
		path string
		want Source
	}{
		{"/Users/a/.nvm/versions/node/v22/bin/node", SourceNVM},
		{"/home/a/.local/share/nvm/versions/node/v22/bin/node", SourceNVM},
		{"/Users/a/.volta/bin/node", SourceVolta},
		{"/Users/a/.local/share/fnm/node-versions/v22/installation/bin/node", SourceFNM},
		{"/Users/a/.asdf/installs/nodejs/22/bin/node", SourceASDF},
		{"/Users/a/.local/share/mise/installs/node/22/bin/node", SourceMise},
		{"/Users/a/.sdkman/candidates/java/21", SourceSDKMAN},
		{"/Users/a/.pyenv/versions/3.12/bin/python", SourcePyenv},
		{"/Users/a/.cargo/bin/rustup", SourceCargo},
		{"/opt/homebrew/bin/git", SourceBrew},
		{"/usr/local/opt/curl/bin/curl", SourceBrew},
		{"/usr/local/Cellar/git/2.50/bin/git", SourceBrew},
		{"/home/linuxbrew/.linuxbrew/bin/git", SourceBrew},
		{"/usr/local/go/bin/go", SourceGo},
		{"/Applications/Foo.app/Contents/MacOS/Foo", SourceApp},
		{"/Users/a/Applications/Foo.app/Contents/MacOS/Foo", SourceApp},
		{"/usr/bin/git", SourceOther},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, WhereFrom(tt.path))
		})
	}
}

func TestSeen(t *testing.T) {
	var s Seen
	assert.True(t, s.First("a"))
	assert.False(t, s.First("a"))
	assert.True(t, s.First("b"))
}

func TestCompactPath(t *testing.T) {
	assert.Equal(t, "~/bin/x", CompactPath("/home/a/bin/x", "/home/a"))
	assert.Equal(t, "/etc/x", CompactPath("/etc/x", "/home/a"))
	assert.Equal(t, "/home/ab/x", CompactPath("/home/ab/x", "/home/a"))
	assert.Equal(t, "/x", CompactPath("/x", ""))
}

func TestExtractVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1", "8.7.1"},
		{"git version 2.50.1 (Apple Git-155)", "2.50.1"},
		{"v22.23.4", "22.23.4"},
		{"uv 0.13.4 (abc 2026-10-01)", "0.13.4"},
		{"go version go1.26.10 darwin/arm64", "1.26.10"},
		{"openjdk version \"21.0.13\" 2026-10-21", "21.0.13"},
		{"no digits here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, ExtractVersion(tt.in))
		})
	}
}

func writeExe(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"), mode))
}

func TestResolveFollowsSymlinkChain(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	real := filepath.Join(dir, "real", "tool")
	writeExe(t, real, 0o755)
	require.NoError(t, os.Symlink(real, filepath.Join(dir, "abs")))
	require.NoError(t, os.Symlink("abs", filepath.Join(dir, "rel")))

	assert.Equal(t, real, Resolve(filepath.Join(dir, "rel")))
	assert.Equal(t, real, Resolve(filepath.Join(dir, "abs")))
	assert.Equal(t, real, Resolve(real))
}

func TestResolveLoopTerminates(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	require.NoError(t, os.Symlink(b, a))
	require.NoError(t, os.Symlink(a, b))
	assert.NotEmpty(t, Resolve(a))
}

func TestResolveMissingPathReturnsInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope", "tool")
	assert.Equal(t, p, Resolve(p))
}

func TestLookupAndExecutable(t *testing.T) {
	dir := t.TempDir()
	extra := t.TempDir()
	writeExe(t, filepath.Join(dir, "tool"), 0o755)
	writeExe(t, filepath.Join(dir, "plain"), 0o644)
	writeExe(t, filepath.Join(extra, "only-extra"), 0o755)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "adir"), 0o755))

	pathEnv := dir + string(os.PathListSeparator) + "/nonexistent"
	assert.Equal(t, filepath.Join(dir, "tool"), Lookup("tool", pathEnv))
	assert.Equal(t, "", Lookup("plain", pathEnv), "non-executable file is skipped")
	assert.Equal(t, "", Lookup("adir", pathEnv), "directory is skipped")
	assert.Equal(t, "", Lookup("only-extra", pathEnv))
	assert.Equal(t, filepath.Join(extra, "only-extra"), Lookup("only-extra", pathEnv, extra))
	assert.Equal(t, "", Lookup("tool", ""))
}

func TestCandidatesSortedDedupedExisting(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"v22.1.0", "v20.9.0", "v24.0.0"} {
		writeExe(t, filepath.Join(dir, "versions", v, "bin", "node"), 0o755)
	}
	glob := filepath.Join(dir, "versions", "*", "bin", "node")
	literal := filepath.Join(dir, "versions", "v20.9.0", "bin", "node")

	got := Candidates(glob, literal, filepath.Join(dir, "missing", "*"), "[")
	assert.Equal(t, []string{
		filepath.Join(dir, "versions", "v20.9.0", "bin", "node"),
		filepath.Join(dir, "versions", "v22.1.0", "bin", "node"),
		filepath.Join(dir, "versions", "v24.0.0", "bin", "node"),
	}, got)
	assert.Empty(t, Candidates())
}

func TestExecutables(t *testing.T) {
	dir := t.TempDir()
	x, n := filepath.Join(dir, "x"), filepath.Join(dir, "n")
	writeExe(t, x, 0o755)
	writeExe(t, n, 0o644)
	assert.Equal(t, []string{x}, Executables([]string{x, n, filepath.Join(dir, "gone")}))
}
