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

// Package uvpython upgrades uv managed Python minor lines when the python Kind's audit asks
// for it (fix_uv_python), verifying that the interpreter uv then selects rejects the
// compromised chain and that uv's launcher links still select it. Anything less is rolled back.
package uvpython

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvenv"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/uvverify"
)

// Kind implements kinds.Kind and kinds.Fixer for uv managed Python upgrades.
type Kind struct{}

// New creates the uvpython Kind.
func New() kinds.Kind { return &Kind{} }

// ID returns the Kind identifier.
func (k *Kind) ID() string { return "uvpython" }

// Describe returns a one-line description.
func (k *Kind) Describe() string { return "uv managed Python interpreter upgrades" }

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
func (k *Kind) FixOrder() int { return kinds.FixUVPython }

// Plan builds one fix per Python minor line the audit requested.
func (k *Kind) Plan(ctx context.Context, env *kinds.Env, findings []kinds.Finding) ([]fixrun.Fix, error) {
	requests := kinds.RequestsFor("uvpython", findings)
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
	if err != nil || dirs.Python == "" {
		return nil, nil
	}
	ue.PythonDir = dirs.Python

	var fixes []fixrun.Fix
	for _, req := range requests {
		fixes = append(fixes, &fix{env: env, uv: ue, uvBin: uvBin, minor: req.Target, minimum: req.Minimum})
	}
	return fixes, nil
}

// fix is one uv Python minor line upgrade.
type fix struct {
	env     *kinds.Env
	uv      *uvenv.Env
	uvBin   string
	minor   string
	minimum string
}

func (f *fix) Kind() string   { return "uvpython" }
func (f *fix) Target() string { return f.minor }

// Run ports fix_uv_python.
func (f *fix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	pythonDir := f.uv.PythonDir
	s.Say("%s", s.Bold("uv managed Python "+f.minor))
	if !uvverify.Ready(ctx, s, f.uvBin) {
		return fixrun.Failed
	}
	if f.minimum != "" {
		s.Say("uv catalogue target: %s or newer within Python %s", f.minimum, f.minor)
	}
	bindir, err := f.uv.BinDir(ctx, "python")
	if err != nil {
		s.Bad("cannot locate uv's Python executable directory")
		return fixrun.Failed
	}
	s.Cmd("%s python upgrade %s", fixrun.Quote(f.uvBin), fixrun.Quote(f.minor))
	s.Say("Only the %s minor line is upgraded. Older patch versions are not uninstalled.", f.minor)
	s.Say("uv can replace a build of the same patch version; complete original installs and links are backed up.")

	matches, _ := filepath.Glob(filepath.Join(pythonDir, "cpython-"+f.minor+".*"))
	for _, d := range matches {
		if fi, err := os.Lstat(d); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			s.Bad("symlinked patch installation is not supported: %s", d)
			return fixrun.Failed
		}
	}
	s.Say("Pinned environments can keep using an old patch. A Python upgrade alone may not fix certifi or pip.")

	if s.DryRun {
		s.Say("[dry-run] would back up complete interpreter installations and preferred links, upgrade, and verify the selected interpreter's TLS")
		return fixrun.Skipped
	}
	if !s.Confirm("Upgrade uv managed Python " + f.minor + " and verify its TLS behavior?") {
		return fixrun.Skipped
	}

	backupRoot := filepath.Join(pythonDir, ".emudhra-backups")
	if err := uvenv.UVPrepareBackups(pythonDir, backupRoot, nil); err != nil {
		s.Bad("cannot prepare Python backups on the installation filesystem")
		return fixrun.Failed
	}
	backup, err := os.MkdirTemp(backupRoot, "python-"+f.minor+"-"+s.Stamp+".")
	if err != nil {
		return fixrun.Failed
	}
	// Reserve rollback metadata before an upgrade can exhaust the filesystem.
	if os.MkdirAll(filepath.Join(backup, "failed-installations"), 0o700) != nil ||
		os.WriteFile(filepath.Join(backup, "original-directory"), []byte(pythonDir+"\n"), 0o600) != nil {
		s.Bad("could not prepare Python recovery metadata; nothing upgraded")
		return fixrun.Failed
	}
	pythonLinks := filepath.Join(backup, "python-links")
	binLinks := filepath.Join(backup, "bin-links")
	kind := string(uvenv.LinkKindPython)
	if uvenv.UVSavePythonInstalls(pythonDir, f.minor, filepath.Join(backup, "installations")) != nil ||
		uvenv.UVSaveLinks(pythonDir, pythonLinks, kind, f.minor, pythonDir) != nil ||
		uvenv.UVSaveLinks(bindir, binLinks, kind, f.minor, pythonDir) != nil {
		s.Bad("could not back up the original interpreter installations and links; nothing upgraded")
		return fixrun.Failed
	}

	res := s.Run.Run(ctx, f.uvBin, "python", "upgrade", f.minor)
	log := strings.TrimRight(res.Stdout+res.Stderr, "\n")
	if log != "" {
		lines := strings.Split(log, "\n")
		for _, l := range lines[max(0, len(lines)-6):] {
			s.Say("    %s", l)
		}
	}

	ok, reason, ver := false, "uv python upgrade failed", ""
	if res.ExitCode == 0 && res.Error == nil {
		reason, ver = f.verify(ctx, bindir, backup)
		ok = reason == ""
	}
	if ok {
		s.OK("selected Python %s rejects the compromised chain on all probed Python trust paths", ver)
		s.Warn("old patch versions remain available; replaced builds are saved in the backup. Re-audit pinned environments.")
		s.Note("uv Python %s original installations and preferred links backed up at %s", f.minor, backup)
		return fixrun.Changed
	}

	s.Bad("%s; restoring the original interpreter installations and links", reason)
	if uvenv.UVRestorePythonInstalls(pythonDir, backup) != nil ||
		uvenv.UVRestoreLinks(pythonDir, pythonLinks, kind, f.minor, pythonDir) != nil ||
		uvenv.UVRestoreLinks(bindir, binLinks, kind, f.minor, pythonDir) != nil {
		s.Bad("interpreter restoration needs manual attention; backups: %s", backup)
		return fixrun.Failed
	}
	s.Say("original interpreter contents and links restored; any new patch installation was retained")
	return fixrun.Failed
}

// verify finds the interpreter uv now selects for the minor line, checks its TLS behaviour and
// that uv's launchers select it. It returns the failure reason ("" when verified) and the
// interpreter's version.
func (f *fix) verify(ctx context.Context, bindir, backup string) (reason, ver string) {
	p, err := f.uv.Read(ctx, "python", "find", "--system", "--managed-python", f.minor)
	if err != nil || p == "" {
		return "could not find the upgraded interpreter", ""
	}
	v := uvverify.Python(ctx, f.env, p, f.minor, f.minimum)
	if !v.Passed() {
		return v.Reason, v.Version
	}
	if r := f.verifyLaunchers(p, v.Version, bindir, backup); r != "" {
		return r, v.Version
	}
	return "", v.Version
}

// verifyLaunchers ports verify_uv_python_launchers: every launcher that was a link before the
// upgrade must still be one, and must select the verified interpreter.
func (f *fix) verifyLaunchers(p, version, bindir, backup string) string {
	expected, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "could not find the upgraded interpreter"
	}
	base := filepath.Dir(filepath.Dir(expected))
	for _, alias := range []string{"python", "python3", "python" + f.minor} {
		if !isLink(filepath.Join(backup, "bin-links", alias)) {
			continue
		}
		current := filepath.Join(bindir, alias)
		if resolved, err := filepath.EvalSymlinks(current); !isLink(current) || err != nil || resolved != expected {
			return "Python launcher " + current + " does not select the verified interpreter"
		}
	}
	suffix := strings.TrimPrefix(filepath.Base(base), "cpython-"+version)
	alias := "cpython-" + f.minor + suffix
	if isLink(filepath.Join(backup, "python-links", alias)) {
		current := filepath.Join(f.uv.PythonDir, alias)
		fi, err := os.Stat(current)
		resolved, rerr := filepath.EvalSymlinks(current)
		if err != nil || !fi.IsDir() || rerr != nil || resolved != base {
			return "Python minor launcher " + current + " does not select the verified interpreter"
		}
	}
	return ""
}

func isLink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}
