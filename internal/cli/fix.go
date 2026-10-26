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

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/registry"
)

const progName = "emudhra-audit-fix"

// newSession builds the fixrun Session for --fix and --undo from the Env.
func newSession(env *kinds.Env, out io.Writer, color bool) *fixrun.Session {
	return &fixrun.Session{
		Run: env.Run, Prompt: env.Prompt, Priv: env.Priv, Host: env.Host,
		DryRun: env.DryRun, Yes: env.Yes, Color: color, Out: out,
		Stamp: time.Now().Format("20060102150405"), TempDir: env.TempDir,
	}
}

func heading(s *fixrun.Session, title string) {
	bold, off := "", ""
	if s.Color {
		bold, off = "\033[1m", "\033[0m"
	}
	_, _ = fmt.Fprintf(s.Out, "%s== %s ==%s\n", bold, title, off)
}

// planFixes asks every Fixer (in registry order) for its fixes. A Kind whose
// Plan fails is reported and skipped; the others still run.
//
// Every Fixer receives ALL findings, not just its own. In the script a fix can
// be scheduled by another tool's audit (a Python finding sets FIXPIP, which
// plans the macOS pip fix; curl, git and Python set FIXSYS, which plans the
// system CA fix), so a Kind must be able to see the findings that concern it.
// A Fixer selects the findings it acts on.
func planFixes(ctx context.Context, env *kinds.Env, s *fixrun.Session, all []kinds.Kind, findings []kinds.Finding) []fixrun.Fix {
	var fixers []kinds.Fixer
	for _, k := range all {
		if fx, ok := k.(kinds.Fixer); ok {
			fixers = append(fixers, fx)
		}
	}
	// The fix order is the script's run_fixes order, not the audit order.
	// SliceStable keeps registry order between Kinds of equal rank.
	sort.SliceStable(fixers, func(i, j int) bool { return fixers[i].FixOrder() < fixers[j].FixOrder() })

	var fixes []fixrun.Fix
	for _, fx := range fixers {
		planned, err := fx.Plan(ctx, env, findings)
		if err != nil {
			s.Bad("could not plan the %s fix: %v", fx.ID(), err)
			continue
		}
		fixes = append(fixes, planned...)
	}
	return fixes
}

// runFixes ports run_fixes: the "Fix" section, the dry-run or confirmation
// banner, the MDM warning, then each fix in registry order, then the counters.
func runFixes(ctx context.Context, env *kinds.Env, out io.Writer, color bool, all []kinds.Kind, findings []kinds.Finding, opts Options) {
	s := newSession(env, out, color)
	heading(s, "Fix")

	only := map[string]bool{}
	for _, id := range registry.ExpandAliases(opts.Only) {
		if id != "" {
			only[id] = true
		}
	}

	var fixes []fixrun.Fix
	for _, f := range planFixes(ctx, env, s, all, findings) {
		if len(only) == 0 || only[f.Kind()] {
			fixes = append(fixes, f)
		}
	}

	if len(fixes) == 0 {
		switch {
		case len(only) == 0:
			s.Say("Nothing to fix: no item has an automated upgrade or trust-store fix planned.")
		default:
			s.Say("Nothing matched --only %s.", strings.Join(opts.Only, ","))
		}
		s.Say("Changed: 0   Failed or refused: 0   Skipped: 0")
		_, _ = fmt.Fprintln(out)
		return
	}

	if env.DryRun {
		s.Say("DRY RUN - nothing will be changed. Each step below is verified on a copy where possible.")
	} else {
		s.Say("Each change asks first, is tested on a copy, is backed up, verified after, and rolled back if it fails.")
	}
	if env.Host.MDM.Enrolled {
		s.Warn("this Mac appears to be enrolled in MDM (%s): IT may overwrite these changes, or want to make them centrally", truncate(env.Host.MDM.Source, 110))
	}

	fixrun.Execute(ctx, s, fixes, only)
	s.Summary(progName)
}

// runUndo ports run_undo: every Undoer reports and restores its own backups.
func runUndo(ctx context.Context, env *kinds.Env, out io.Writer, color bool, all []kinds.Kind, opts Options) int {
	s := newSession(env, out, color)
	heading(s, "Undo")

	only := map[string]bool{}
	for _, id := range registry.ExpandAliases(opts.Only) {
		if id != "" {
			only[id] = true
		}
	}

	failed := false
	for _, k := range all {
		u, ok := k.(kinds.Undoer)
		if !ok || (len(only) > 0 && !only[k.ID()]) {
			continue
		}
		if err := u.Undo(ctx, env, s); err != nil {
			s.Bad("%s: %v", k.ID(), err)
			failed = true
		}
	}
	s.Say("Homebrew and uv upgrades are not covered by --undo (see the notes printed by --fix).")
	_, _ = fmt.Fprintln(out)
	if failed {
		return 2
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
