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

// Package uvtools upgrades uv tool environments when the python Kind's audit asks for it
// (fix_uv_tool). The whole environment and its executable links are saved first, uv upgrades the
// tool on the Python it already uses, and the result is verified; anything less is rolled back.
package uvtools

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds/python"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvenv"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvverify"
)

// Kind implements kinds.Kind and kinds.Fixer for uv tool environments.
type Kind struct{}

// New creates the uvtools Kind.
func New() kinds.Kind { return &Kind{} }

// ID returns the Kind identifier.
func (k *Kind) ID() string { return "uvtools" }

// Describe returns a one-line description.
func (k *Kind) Describe() string { return "uv tool environment upgrades" }

// Applicable reports macOS and Linux only.
func (k *Kind) Applicable(h platform.Host) kinds.Applicability {
	if h.OS != "darwin" && h.OS != "linux" {
		return kinds.Applicability{Applies: false, Reason: "macOS and Linux only"}
	}
	return kinds.Applicability{Applies: true}
}

// Audit returns no findings: the audit lives in the python Kind, which asks for upgrades
// through Finding.Requests.
func (k *Kind) Audit(context.Context, *kinds.Env) ([]kinds.Finding, error) { return nil, nil }

// FixOrder is where this Kind's fixes run in --fix.
func (k *Kind) FixOrder() int { return kinds.FixUVTools }

// Plan builds one fix per tool environment the audit requested.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	requests := kinds.RequestsFor("uvtools", findings)
	if len(requests) == 0 {
		return nil, nil
	}
	uvBin := uvenv.FindUV(env)
	if uvBin == "" {
		return nil, nil
	}
	ue := uvenv.NewEnv(env, uvBin)
	ue.WorkDir = env.TempDir
	dirs, err := ue.EnvironmentDirs(ctx)
	if err != nil {
		return nil, nil
	}
	ue.ToolDir = dirs.Tool
	if dirs.Python != "" {
		ue.PythonDir = dirs.Python
	}

	var fixes []fixrun.Fix
	for _, req := range requests {
		fixes = append(fixes, &fix{env: env, uv: ue, uvBin: uvBin, name: req.Target})
	}
	return fixes, nil
}

// fix is one uv tool environment upgrade.
type fix struct {
	env   *kinds.Env
	uv    *uvenv.Env
	uvBin string
	name  string
}

func (f *fix) Kind() string   { return "uvtools" }
func (f *fix) Target() string { return f.name }

// Run ports fix_uv_tool.
func (f *fix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	s.Say("%s", s.Bold("uv tool "+f.name))
	if !uvenv.ToolNameSafe(f.name) {
		s.Bad("unsupported tool name")
		return fixrun.Failed
	}
	if !uvverify.Ready(ctx, s, f.uvBin) {
		return fixrun.Failed
	}

	toolsDir := f.uv.ToolDir
	dir := filepath.Join(toolsDir, f.name)
	if toolsDir == "" || isLink(dir) || !isRegular(filepath.Join(dir, "uv-receipt.toml")) {
		s.Bad("tool environment is missing, symlinked, or has no uv receipt")
		return fixrun.Failed
	}

	// Preserve the tool's own Python: its version and implementation.
	p := filepath.Join(dir, "bin", "python")
	info, err := python.Info(ctx, f.env, p)
	if err != nil || info == nil || info.Implementation != "cpython" || info.Version == "" || info.BasePrefix == "" {
		s.Bad("cannot preserve this tool's Python version and implementation automatically")
		return fixrun.Failed
	}
	minor := info.Version
	if i := strings.LastIndex(minor, "."); i >= 0 {
		minor = minor[:i]
	}
	var target string
	if f.uv.ManagedMinor(info.BasePrefix, info.Version, info.Implementation) != "" {
		target, _ = f.uv.Read(ctx, "python", "find", "--system", "--managed-python", minor)
	} else {
		// Preserve the exact external interpreter rather than switching package managers.
		target = filepath.Join(info.BasePrefix, "bin", "python3")
	}
	if !discover.IsExecutable(target) {
		s.Bad("cannot locate a usable Python %s interpreter", minor)
		return fixrun.Failed
	}
	bindir, err := f.uv.BinDir(ctx, "tool")
	if err != nil {
		s.Bad("cannot locate uv's tool executable directory")
		return fixrun.Failed
	}
	if !f.entrypointsSafe(ctx, dir, bindir) {
		s.Bad("recorded executable paths differ from the current tool bin directory, or an entry point belongs to another tool")
		s.Say("Use the original UV_TOOL_BIN_DIR and resolve conflicting executable links before retrying. Nothing upgraded.")
		return fixrun.Failed
	}

	s.Cmd("%s tool upgrade %s --python %s --no-python-downloads", fixrun.Quote(f.uvBin), fixrun.Quote(f.name), fixrun.Quote(target))
	s.Say("uv preserves recorded version constraints, sources, extras, and install options. Tool packages and dependencies may upgrade within those constraints.")
	if s.DryRun {
		s.Say("[dry-run] would back up the full environment and its executable links, upgrade, then verify dependencies and Python TLS")
		return fixrun.Skipped
	}
	if !s.Confirm("Upgrade uv tool " + f.name + " with Python " + minor + ", retaining its recorded requirements?") {
		return fixrun.Skipped
	}

	// A directory inside the tools directory is read by uv as an installed tool, so the backups
	// live beside it.
	backupRoot := toolsDir + ".emudhra-backups"
	if err := uvenv.UVPrepareBackups(toolsDir, backupRoot, nil); err != nil {
		s.Bad("cannot prepare tool backups on the installation filesystem")
		return fixrun.Failed
	}
	backup, err := os.MkdirTemp(backupRoot, "tool-"+f.name+"-"+s.Stamp+".")
	if err != nil {
		return fixrun.Failed
	}
	if os.WriteFile(filepath.Join(backup, "original-directory"), []byte(dir+"\n"), 0o600) != nil {
		s.Bad("could not prepare tool recovery metadata; nothing upgraded")
		return fixrun.Failed
	}
	if uvenv.CopyTree(dir, filepath.Join(backup, "environment")) != nil ||
		uvenv.UVSaveLinks(bindir, filepath.Join(backup, "bin-links"), string(uvenv.LinkKindTool), dir, "") != nil {
		s.Bad("could not back up the tool and its links; nothing upgraded")
		return fixrun.Failed
	}

	res := s.Run.Run(ctx, f.uvBin, "tool", "upgrade", f.name, "--python", target, "--no-python-downloads")
	if log := strings.TrimRight(res.Stdout+res.Stderr, "\n"); log != "" {
		lines := strings.Split(log, "\n")
		for _, l := range lines[max(0, len(lines)-6):] {
			s.Say("    %s", l)
		}
	}

	reason := "uv tool upgrade failed"
	if res.ExitCode == 0 && res.Error == nil {
		reason = ""
		if v := uvverify.Python(ctx, f.env, p, minor, ""); !v.Passed() {
			reason = v.Reason
		} else if _, err := f.uv.Read(ctx, "pip", "check", "--python", p); err != nil {
			reason = "dependency verification failed"
		}
	}
	if reason == "" {
		s.OK("%s dependencies are consistent; its Python trust paths reject the compromised chain", f.name)
		s.Say("Application clients and native binaries have not been probed.")
		s.Note("uv tool %s environment and executable links backed up at %s", f.name, backup)
		return fixrun.Changed
	}

	s.Bad("%s; restoring the tool environment and executable links", reason)
	if uvenv.UVRestoreTool(dir, bindir, backup) != nil {
		s.Bad("restoration needs manual attention; backups: %s", backup)
	} else {
		s.Say("original tool environment and links restored")
	}
	return fixrun.Failed
}

// entrypointsSafe ports uv_tool_entrypoints_safe: uv removes entry points at the paths recorded
// in the receipt, so ask uv for them and fail closed if any lies outside the tool bin directory,
// is in an unexpected format, or now belongs to another installation.
func (f *fix) entrypointsSafe(ctx context.Context, dir, bindir string) bool {
	listing, err := f.uv.Read(ctx, "tool", "list", "--show-paths")
	if err != nil {
		return false
	}
	safe, err := uvenv.UVToolEntrypointsSafe(f.name, dir, bindir, listing)
	return err == nil && safe
}

func isLink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func isRegular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
