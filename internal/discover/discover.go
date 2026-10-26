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

// Package discover holds the helpers every Kind needs to find installations
// of a tool: symlink resolution, de-duplication, PATH lookup, glob-based
// candidate collection, install-source classification and version
// extraction. They port resolve(), first_time(), where_from(),
// compact_path() and the *_candidates() functions of the legacy script.
//
// It does not run commands (that belongs to internal/exec), so a Kind runs
// "<tool> --version" through its Runner and hands the output to
// ExtractVersion.
package discover

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxLinks bounds symlink chasing, as the script's resolve() did.
const maxLinks = 20

// Resolve follows symlinks (up to 20 hops) and returns an absolute,
// symlink-free directory plus the final name. If the path cannot be
// resolved it is returned unchanged, matching resolve().
func Resolve(p string) string {
	n := 0
	for n < maxLinks {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			break
		}
		t, err := os.Readlink(p)
		if err != nil {
			break
		}
		if filepath.IsAbs(t) {
			p = t
		} else {
			p = filepath.Join(filepath.Dir(p), t)
		}
		n++
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return p
	}
	return filepath.Join(dir, filepath.Base(p))
}

// Seen records keys already visited so a tool reached through several
// routes (PATH, a version manager, a symlink) is audited once. It ports
// first_time(). The zero value is ready to use. It is not safe for
// concurrent use.
type Seen struct {
	keys map[string]struct{}
}

// First reports whether key has not been seen before, and records it.
func (s *Seen) First(key string) bool {
	if s.keys == nil {
		s.keys = make(map[string]struct{})
	}
	if _, ok := s.keys[key]; ok {
		return false
	}
	s.keys[key] = struct{}{}
	return true
}

// Source names where an installation came from.
type Source string

// Install sources, matching the script's where_from() values.
const (
	SourceNVM    Source = "nvm"
	SourceVolta  Source = "volta"
	SourceFNM    Source = "fnm"
	SourceASDF   Source = "asdf"
	SourceMise   Source = "mise"
	SourceSDKMAN Source = "sdkman"
	SourcePyenv  Source = "pyenv"
	SourceCargo  Source = "cargo"
	SourceBrew   Source = "brew"
	SourceGo     Source = "golang"
	SourceApp    Source = "app"
	SourceOther  Source = "other"
)

// WhereFrom classifies an installation path by the package or version
// manager that owns it. It ports where_from(); the order of checks matters
// and is the script's.
func WhereFrom(path string) Source {
	switch {
	case has(path, "/.nvm/") || has(path, "/nvm/versions/node/"):
		return SourceNVM
	case has(path, "/.volta/"):
		return SourceVolta
	case has(path, "/fnm/"):
		return SourceFNM
	case has(path, "/.asdf/"):
		return SourceASDF
	case has(path, "/mise/"):
		return SourceMise
	case has(path, "/.sdkman/"):
		return SourceSDKMAN
	case has(path, "/.pyenv/"):
		return SourcePyenv
	case has(path, "/.cargo/"):
		return SourceCargo
	case has(path, "/Cellar/") || strings.HasPrefix(path, "/opt/homebrew/") ||
		strings.HasPrefix(path, "/usr/local/opt/") || has(path, "/.linuxbrew/"):
		return SourceBrew
	case strings.HasPrefix(path, "/usr/local/go/"):
		return SourceGo
	case strings.HasPrefix(path, "/Applications/") || has(path, "/Applications/"):
		return SourceApp
	}
	return SourceOther
}

func has(path, frag string) bool { return strings.Contains(path, frag) }

// CompactPath replaces a leading home directory with ~ for display. It
// ports compact_path().
func CompactPath(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+"/") {
		return "~/" + strings.TrimPrefix(p, home+"/")
	}
	return p
}

// Lookup finds an executable on the given PATH string (colon separated),
// like `command -v`, without running anything. extra directories are
// searched after PATH. It returns "" when nothing is found.
func Lookup(name, pathEnv string, extra ...string) string {
	dirs := append(filepath.SplitList(pathEnv), extra...)
	for _, d := range dirs {
		if d == "" {
			d = "."
		}
		p := filepath.Join(d, name)
		if IsExecutable(p) {
			return p
		}
	}
	return ""
}

// IsExecutable reports whether p is a regular file (after symlinks) with an
// execute bit set.
func IsExecutable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

// Candidates expands glob patterns and returns the existing matches in a
// stable order, de-duplicated. A literal path (no glob characters) is kept
// if it exists. It is the shared core of the script's *_candidates()
// functions: each Kind supplies its own pattern list.
func Candidates(patterns ...string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			if _, ok := seen[m]; ok {
				continue
			}
			if _, err := os.Stat(m); err != nil {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

// Executables filters paths to those that are executable files.
func Executables(paths []string) []string {
	var out []string
	for _, p := range paths {
		if IsExecutable(p) {
			out = append(out, p)
		}
	}
	return out
}

var versionRE = regexp.MustCompile(`\d+(?:\.\d+)+(?:[-+._][0-9A-Za-z]+)*`)

// ExtractVersion returns the first dotted version found in a tool's
// --version output ("curl 8.7.1 (x86_64-...)" gives "8.7.1"), or "" if none
// is present. Tools whose output is irregular (Java, Go) parse their own.
func ExtractVersion(output string) string {
	return versionRE.FindString(output)
}
