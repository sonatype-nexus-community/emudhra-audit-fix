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

// Package boundaries enforces which packages may touch privileged or
// interactive facilities. It holds only a test, run by `go test ./...`.
//
//   - the os/exec import: only internal/exec
//   - the "sudo" string literal: only internal/privilege
//   - the "/dev/tty" string literal: only internal/prompt
//
// Test files are exempt: they may name these strings to assert on them.
package boundaries

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type rule struct {
	what    string
	owner   string
	matches func(importPath, literal string) bool
}

var rules = []rule{
	{"os/exec import", "internal/exec", func(imp, _ string) bool { return imp == "os/exec" }},
	{`"sudo" literal`, "internal/privilege", func(_, lit string) bool { return lit == "sudo" }},
	{`"/dev/tty" literal`, "internal/prompt", func(_, lit string) bool { return lit == "/dev/tty" }},
}

// violations returns one message per use of a restricted facility outside
// the package that owns it.
func violations(root string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Skip VCS and tool directories (.git, .claude/worktrees holds
			// full copies of the repo) and the unmaintained legacy script.
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || rel == "legacy" || rel == "design") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		check := func(imp, lit string, pos token.Pos) {
			for _, r := range rules {
				if r.matches(imp, lit) && !strings.HasPrefix(rel, r.owner+"/") {
					out = append(out, fset.Position(pos).String()+": "+r.what+" outside "+r.owner)
				}
			}
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			check(p, "", im.Pos())
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, uerr := strconv.Unquote(bl.Value); uerr == nil {
					check("", s, bl.Pos())
				}
			}
			return true
		})
		return nil
	})
	return out, err
}

func TestBoundaries(t *testing.T) {
	got, err := violations(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		t.Error(v)
	}
}

// TestBoundariesDetectsViolations proves the check is not vacuous.
func TestBoundariesDetectsViolations(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "internal", "somekind")
	if err := mkdir(bad); err != nil {
		t.Fatal(err)
	}
	src := "package somekind\n\nimport _ \"os/exec\"\n\nvar a = \"sudo\"\nvar b = \"/dev/tty\"\n"
	if err := writeFile(filepath.Join(bad, "x.go"), src); err != nil {
		t.Fatal(err)
	}
	got, err := violations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 violations, got %d: %v", len(got), got)
	}
}
