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

// Package fixrun is the toolkit and runner for --fix and --undo. It ports the
// script's fix machinery: the fx_* output helpers, the Changed / Failed /
// Skipped counters, need_sudo and as_root, and the timestamped backup scheme
// (FILE.pre-emudhra-STAMP, restored with cp -p so owner and mode survive).
//
// A Kind's fix is a Fix. The runner never reaches into a Fix: each one says
// what it will do, handles dry-run itself through Session.DryRun, asks
// through Session.Confirm, backs up, applies, verifies and restores on failure
// using the Session, then returns an Outcome.
package fixrun

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
)

// BackupTag is the infix of every backup this program makes; --undo finds
// backups by it (the script's BACKUP_TAG).
const BackupTag = "pre-emudhra"

// Outcome is what a Fix reports; the runner counts it.
type Outcome int

const (
	// Changed means the machine was modified and verified.
	Changed Outcome = iota
	// Failed means the fix was attempted or refused for cause; anything it
	// touched has been restored.
	Failed
	// Skipped means nothing was done: declined, already clean, not found, or
	// a dry run.
	Skipped
)

// Fix is one remediation of one thing (a JDK, a bundle, an nvm Node).
type Fix interface {
	// Kind is the owning Kind's ID, for --only and the summary.
	Kind() string
	// Target names what is fixed, for messages.
	Target() string
	// Run does the whole fix against the Session and reports the outcome.
	// It must not change anything when s.DryRun is true: it prints the plan
	// (and verifies on a copy where it can) and returns Skipped.
	Run(ctx context.Context, s *Session) Outcome
}

// Session is everything a Fix may use. All output goes through it.
type Session struct {
	Run    exec.Runner
	Prompt prompt.Prompter
	Priv   privilege.Escalator
	Host   platform.Host

	DryRun bool
	Yes    bool
	// Color enables ANSI in the output helpers.
	Color bool
	Out   io.Writer

	// Stamp is the timestamp in this run's backup names; one per run.
	Stamp string
	// TempDir is a private scratch directory for building patched copies.
	TempDir string

	mu     sync.Mutex
	counts map[Outcome]int
	notes  []string
}

// ANSI codes, as the script's C_* variables.
const (
	cRed = "\033[31m"
	cGrn = "\033[32m"
	cYel = "\033[33m"
	cDim = "\033[2m"
	cBld = "\033[1m"
	cOff = "\033[0m"
)

func (s *Session) c(code string) string {
	if s.Color {
		return code
	}
	return ""
}

func (s *Session) printf(format string, a ...any) {
	if s.Out == nil {
		return
	}
	_, _ = fmt.Fprintf(s.Out, format, a...)
}

// Say prints a plain indented line (fx_say).
func (s *Session) Say(format string, a ...any) { s.printf("  %s\n", fmt.Sprintf(format, a...)) }

// Bold wraps text in bold when colour is on, for headings inside Say.
func (s *Session) Bold(text string) string { return s.c(cBld) + text + s.c(cOff) }

// Warn prints a warning (fx_warn).
func (s *Session) Warn(format string, a ...any) {
	s.printf("  %s! %s%s\n", s.c(cYel), fmt.Sprintf(format, a...), s.c(cOff))
}

// OK prints a success line (fx_ok).
func (s *Session) OK(format string, a ...any) {
	s.printf("  %s✓ %s%s\n", s.c(cGrn), fmt.Sprintf(format, a...), s.c(cOff))
}

// Bad prints a failure line (fx_bad).
func (s *Session) Bad(format string, a ...any) {
	s.printf("  %s✗ %s%s\n", s.c(cRed), fmt.Sprintf(format, a...), s.c(cOff))
}

// Cmd prints a command that is, or would be, run (fx_cmd).
func (s *Session) Cmd(format string, a ...any) {
	s.printf("  %s  $ %s%s\n", s.c(cDim), fmt.Sprintf(format, a...), s.c(cOff))
}

// Confirm asks y/N, honouring --yes. In a dry run it is never called by a
// well-behaved Fix; if it is, it answers no.
func (s *Session) Confirm(question string) bool {
	if s.DryRun {
		return false
	}
	return s.Prompt.Confirm("  "+question, s.Yes)
}

// ConfirmAgree is for destructive steps. --yes never answers it.
func (s *Session) ConfirmAgree(warning string) bool {
	if s.DryRun {
		return false
	}
	return s.Prompt.ConfirmAgree(warning)
}

// Note records a line for the closing "Backups and undo notes".
func (s *Session) Note(format string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes = append(s.notes, fmt.Sprintf(format, a...))
}

// Notes returns the recorded notes in order.
func (s *Session) Notes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notes...)
}

// Counts returns how many fixes ended in each Outcome.
func (s *Session) Counts() (changed, failed, skipped int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[Changed], s.counts[Failed], s.counts[Skipped]
}

func (s *Session) count(o Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = map[Outcome]int{}
	}
	s.counts[o]++
}

// NeedRoot ports need_sudo: it reports whether writing path needs root and,
// if it does but sudo is unavailable, says so and returns an error. A nil
// error means the write can proceed (with or without AsRoot).
func (s *Session) NeedRoot(path string) (needs bool, err error) {
	if s.Priv.IsRoot() || !s.Priv.Needs(path) {
		return false, nil
	}
	if !s.Priv.HasSudo() {
		s.Bad("need root to write %s but sudo is not available - run this program as root", path)
		return true, fmt.Errorf("need root to write %s but sudo is not available", path)
	}
	return true, nil
}

// AsRoot ports as_root: print the command, and run it (through sudo when
// needed) unless this is a dry run.
func (s *Session) AsRoot(ctx context.Context, name string, args ...string) error {
	line := name
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	if !s.Priv.IsRoot() && s.Priv.HasSudo() {
		s.Cmd("sudo %s", line)
	} else {
		s.Cmd("%s", line)
	}
	if s.DryRun {
		return nil
	}
	return s.Priv.AsRoot(ctx, false, name, args...)
}

// BackupPath is where this run's backup of path lives.
func (s *Session) BackupPath(path string) string {
	return path + "." + BackupTag + "-" + s.Stamp
}

// Backup copies path to BackupPath(path) with cp -p (owner and mode kept), as
// root when path needs it, and records an undo note. Nothing happens in a dry
// run beyond printing the command.
func (s *Session) Backup(ctx context.Context, path string) (string, error) {
	bak := s.BackupPath(path)
	if err := s.AsRoot(ctx, "cp", "-p", path, bak); err != nil {
		return "", fmt.Errorf("backup of %s failed: %w", path, err)
	}
	if !s.DryRun {
		s.Note("%s  ->  %s", path, bak)
	}
	return bak, nil
}

// Restore copies backup over path with cp -p, as root when needed.
func (s *Session) Restore(ctx context.Context, backup, path string) error {
	return s.AsRoot(ctx, "cp", "-p", backup, path)
}

// NewestBackup ports newest_backup: the most recent FILE.pre-emudhra-*, or ""
// when there is none. Names sort chronologically because the stamp is
// YYYYMMDDHHMMSS.
func NewestBackup(path string) string {
	matches, _ := filepath.Glob(path + "." + BackupTag + "-*")
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[len(matches)-1]
}

// Execute runs fixes in order, counting each Outcome, and returns a summary.
// One Fix failing never stops the others: a failed fix is counted and the run
// carries on, as the script does.
func Execute(ctx context.Context, s *Session, fixes []Fix, only map[string]bool) {
	for _, f := range fixes {
		if len(only) > 0 && !only[f.Kind()] {
			continue
		}
		if ctx.Err() != nil {
			s.Warn("interrupted - not running the remaining fixes")
			return
		}
		out := f.Run(ctx, s)
		s.count(out)
	}
}

// Summary prints the closing counters, the backup notes and the undo hint (the
// tail of run_fixes).
func (s *Session) Summary(prog string) {
	changed, failed, skipped := s.Counts()
	s.printf("\n  %sChanged: %d   Failed or refused: %d   Skipped: %d%s\n", s.c(cBld), changed, failed, skipped, s.c(cOff))
	if notes := s.Notes(); len(notes) > 0 {
		s.printf("  Backups and undo notes:\n")
		for _, n := range notes {
			s.printf("    %s\n", n)
		}
		s.printf("  Restore system files and JDK stores with: %s --undo\n", prog)
	}
}

// Quote makes s safe to paste into a shell, as the script's `printf '%q'` does for the commands
// it shows: safe characters pass through, anything else is backslash-escaped, and a string with a
// newline (which a backslash cannot express) is single-quoted. The empty string is ”.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, "\n'") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_@%+=:,./-", r):
		default:
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
