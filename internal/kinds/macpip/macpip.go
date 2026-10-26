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

// Package macpip implements the macOS built-in pip fix.
// It has no audit - it adds the PIP_CERT line to Apple's Python sitecustomize.py
// when the python Kind's audit finds that /usr/bin/python3 needs pip guidance.
package macpip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
)

// Kind implements kinds.Kind and kinds.Fixer for macOS built-in pip.
type Kind struct{}

// New creates a new macpip Kind.
func New() kinds.Kind {
	return &Kind{}
}

// ID returns the stable identifier for this Kind.
func (k *Kind) ID() string {
	return "macpip"
}

// Describe returns a one-line human description.
func (k *Kind) Describe() string {
	return "macOS built-in pip (sitecustomize.py sets PIP_CERT)"
}

// Applicable reports whether this Kind makes sense on this host.
// macOS only - the sitecustomize.py path does not exist on Linux.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	if h.OS != "darwin" {
		return kinds.Applicability{
			Applies: false,
			Reason:  "macOS only (Apple Python sitecustomize does not exist on Linux)",
		}
	}
	return kinds.Applicability{
		Applies: true,
		Reason:  "",
	}
}

// Audit returns no findings - the macpip Kind has no audit of its own.
// It is triggered by findings from the python Kind that set NeedsPipGuidance.
func (k *Kind) Audit(ctx context.Context, env *kinds.Env) ([]kinds.Finding, error) {
	return nil, nil
}

// FixOrder implements kinds.Fixer: where this Kind's fix runs in --fix.
func (k *Kind) FixOrder() int { return kinds.FixMacPip }

// Plan returns fixes for Python findings that need pip guidance.
// This ports fix_macos_pip() from the bash script (lines 2390-2426).
// It looks for findings with NeedsPipGuidance and HasFix set.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	// Check if we should offer the macOS pip fix
	// The script sets FIXPIP=1 when /usr/bin/python3 is affected (line 1198)
	// and plan_add macpip /usr/bin/python3 (line 351)
	// report() plans it only inside the bad branch (AFFECTED or LIKELY-AFFECTED):
	// a Python that rejects the chain (status OK) but has an old pip sets the flag
	// and is NOT fixed, exactly as in the script.
	for _, f := range findings {
		if f.NeedsPipGuidance && f.HasFix && f.Status().IsBad() {
			// Found a python finding that needs pip guidance
			// Return one fix for /usr/bin/python3
			return []fixrun.Fix{&fix{}}, nil
		}
	}
	return nil, nil
}

// Undo implements kinds.Undoer. It ports the macpip part of run_undo (lines 3151-3154).
func (k *Kind) Undo(ctx context.Context, env *kinds.Env, s *fixrun.Session) error {
	// The script checks: if [ "$(uname)" = Darwin ] && [ -x /usr/bin/python3 ]; then
	if env.Host.OS != "darwin" {
		return nil
	}

	// Find stdlib directory
	result := env.Run.Run(ctx, "/usr/bin/python3", "-c", `import sysconfig; print(sysconfig.get_path("stdlib"))`)
	if result.Error != nil || result.Stdout == "" {
		return nil // python3 not found or error, skip
	}
	stdlib := strings.TrimSpace(result.Stdout)
	if stdlib == "" {
		return nil
	}

	siteFile := filepath.Join(stdlib, "sitecustomize.py")
	backup := fixrun.NewestBackup(siteFile)
	if backup == "" {
		return nil // no backup found
	}

	s.Say("%s", s.Bold(siteFile))
	s.Say("restore from %s", backup)

	if s.DryRun {
		s.Say("[dry-run] would restore it")
		return nil
	}

	if !s.Confirm(fmt.Sprintf("Restore %s from that backup?", siteFile)) {
		s.Say("skipped")
		return nil
	}

	if _, err := s.NeedRoot(siteFile); err != nil {
		return err
	}

	if err := s.Restore(ctx, backup, siteFile); err != nil {
		s.Bad("restore failed")
		return err
	}

	s.OK("restored")
	return nil
}

// fix implements fixrun.Fix for macOS pip sitecustomize.
type fix struct {
	stdlibDir string // discovered during Run
}

// Kind returns the Kind ID.
func (f *fix) Kind() string { return "macpip" }

// Target returns a description of what is being fixed.
func (f *fix) Target() string {
	return "Apple Python sitecustomize.py"
}

// Run performs the fix. It ports fix_macos_pip (lines 2390-2426).
func (f *fix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	py := "/usr/bin/python3"

	s.Say("")
	s.Say("%s  (%s)", s.Bold("macOS built-in pip"), py)

	// Check if /usr/bin/python3 exists and get stdlib directory
	// Line 2394: [ -x "$py" ] || { fx_warn "not found"; ... }
	// Line 2395-2396: d=$("$py" -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
	result := s.Run.Run(ctx, py, "-c", `import sysconfig; print(sysconfig.get_path("stdlib"))`)
	if result.Error != nil {
		s.Warn("not found")
		return fixrun.Skipped
	}

	f.stdlibDir = strings.TrimSpace(result.Stdout)
	if f.stdlibDir == "" {
		s.Warn("could not locate the stdlib directory")
		return fixrun.Skipped
	}

	// Verify directory exists
	if stat, err := os.Stat(f.stdlibDir); err != nil || !stat.IsDir() {
		s.Warn("could not locate the stdlib directory")
		return fixrun.Skipped
	}

	siteFile := filepath.Join(f.stdlibDir, "sitecustomize.py")
	line := `import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")`

	// Check if already configured
	// Line 2399: if [ -f "$f" ] && grep -qF "$line" "$f"; then fx_ok "already configured" ...
	if _, err := os.Stat(siteFile); err == nil {
		// File exists, check if line is already present
		contents, err := os.ReadFile(siteFile)
		if err == nil && strings.Contains(string(contents), line) {
			s.OK("already configured in %s", siteFile)
			return fixrun.Skipped
		}
	}

	// Print guidance
	// Line 2400: fx_say "this points Apple's pip at /etc/ssl/cert.pem..."
	s.Say("this points Apple's pip at /etc/ssl/cert.pem, so it only helps once that file is patched")

	// Check for Xcode/CommandLineTools warnings
	// Lines 2401-2404
	if strings.Contains(f.stdlibDir, "/Xcode.app/") {
		s.Warn("this directory is inside Xcode: updating Xcode will overwrite this change. A virtualenv or Homebrew Python avoids that.")
	} else if strings.Contains(f.stdlibDir, "/CommandLineTools/") {
		s.Warn("this directory is inside the Command Line Tools: updating them will overwrite this change. A virtualenv or Homebrew Python avoids that.")
	}

	s.Say("would append one line to %s (new file if absent)", siteFile)

	// Dry run: print what would be done and stop
	// Lines 2406-2410
	if s.DryRun {
		needs, _ := s.NeedRoot(f.stdlibDir)
		if _, err := os.Stat(siteFile); err == nil {
			// File exists
			s.Cmd("cp -p %s %s.pre-emudhra-STAMP", siteFile, siteFile)
		}
		if needs {
			s.Cmd("echo '%s' | sudo tee -a %s", line, siteFile)
			s.Cmd("sudo chmod 644 %s", siteFile)
		} else {
			s.Cmd("echo '%s' | tee -a %s", line, siteFile)
			s.Cmd("chmod 644 %s", siteFile)
		}
		return fixrun.Skipped
	}

	// Confirm before proceeding
	// Line 2412: confirm "Add that line to $f?"
	if !s.Confirm(fmt.Sprintf("Add that line to %s?", siteFile)) {
		s.Say("skipped")
		return fixrun.Skipped
	}

	// Check for root access
	// Line 2413: need_sudo "$d"
	if _, err := s.NeedRoot(f.stdlibDir); err != nil {
		return fixrun.Failed
	}

	// Backup existing file if it exists
	// Line 2415: if [ -f "$f" ]; then bak="..." ; as_root cp -p "$f" "$bak" ...
	var backupPath string
	if _, err := os.Stat(siteFile); err == nil {
		backupPath, err = s.Backup(ctx, siteFile)
		if err != nil {
			s.Bad("backup failed: %v", err)
			return fixrun.Failed
		}
	}

	// Apply the fix
	// Lines 2416-2417: printf '%s\n' "$line" | $SUDO tee -a "$f" >/dev/null && $SUDO chmod 644 "$f"
	s.Cmd("echo '...' | tee -a %s", siteFile)
	s.Cmd("chmod 644 %s", siteFile)

	// Write/append to the file
	if err := s.AsRoot(ctx, "sh", "-c", fmt.Sprintf("printf '%%s\\n' %q >> %q && chmod 644 %q", line, siteFile, siteFile)); err != nil {
		s.Bad("apply failed: %v", err)
		if backupPath != "" {
			_ = s.Restore(ctx, backupPath, siteFile)
		}
		return fixrun.Failed
	}

	// Verify: check if python still starts
	// Line 2418: if "$py" -I -c 'import sys' >/dev/null 2>&1 ...
	verifyResult := s.Run.Run(ctx, py, "-I", "-c", "import sys")
	if verifyResult.Error != nil {
		s.Bad("%s no longer starts - rolling back", py)
		if backupPath != "" {
			_ = s.Restore(ctx, backupPath, siteFile)
		} else {
			// No backup means we created the file - remove it
			_ = s.AsRoot(ctx, "rm", "-f", siteFile)
		}
		return fixrun.Failed
	}

	// Success
	// Line 2419-2420: fx_ok "applied; $py still starts..."
	s.OK("applied; %s still starts. Re-run the audit to see pip's result.", py)
	// Note about what was done
	if backupPath == "" {
		// No backup means we created a new file
		s.Note("%s: created (delete the line to undo)", siteFile)
	}
	// Note: if backupPath != "", s.Backup already added the note
	return fixrun.Changed
}
