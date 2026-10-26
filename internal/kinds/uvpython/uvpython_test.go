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

package uvpython

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// rig is a real directory layout with a stub uv whose `python upgrade` runs a script the test
// supplies, so the fixer's backups, verification and rollback act on real files.
type rig struct {
	t         *testing.T
	root      string
	home, bin string
	pyDir     string
	launchers string
	env       *kinds.Env
}

func newRig(t *testing.T) *rig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	r := &rig{t: t, root: root, home: filepath.Join(root, "home"), bin: filepath.Join(root, "bin"),
		pyDir: filepath.Join(root, "uvpython"), launchers: filepath.Join(root, "launchers")}
	for _, d := range []string{r.home, r.bin, r.pyDir, r.launchers} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	uv := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *--version*) echo 'uv 0.13.4' ;;\n" +
		"  *\"python dir --bin\"*) echo " + r.launchers + " ;;\n" +
		"  *\"python dir\"*) echo " + r.pyDir + " ;;\n" +
		"  *\"python upgrade\"*) sh " + filepath.Join(root, "upgrade.sh") + " ; exit $? ;;\n" +
		"  *\"python find\"*) cat " + filepath.Join(root, "find.txt") + " || exit 1 ;;\n" +
		"esac\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte(uv), 0o755))
	r.script("exit 0")
	r.env = testutil.NewTestEnvT(t)
	r.env.Run = exec.NewRealRunner()
	r.env.Environ = map[string]string{"HOME": r.home, "PATH": r.bin + ":/usr/bin:/bin"}
	return r
}

// script sets what `uv python upgrade` does.
func (r *rig) script(body string) {
	require.NoError(r.t, os.WriteFile(filepath.Join(r.root, "upgrade.sh"), []byte(body+"\n"), 0o644))
}

func (r *rig) find(p string) {
	require.NoError(r.t, os.WriteFile(filepath.Join(r.root, "find.txt"), []byte(p+"\n"), 0o644))
}

// interpreter is the stub python: its metadata, and every probed URL answered as the
// compromised chain being rejected (certerr) or trusted (ok), except the control.
func interpreter(ver, pip string, trusting bool) string {
	answer, pipErr := "certerr", "SSLError CERTIFICATE_VERIFY_FAILED"
	if trusting {
		answer, pipErr = "ok", "ERROR: No matching distribution found"
	}
	// `pip download --index-url URL/simple/` : any HTTP answer means the handshake was accepted.
	pipMode := "if [ \"$3\" = -m ]; then case \"$*\" in *github.com*) echo 'ERROR: No matching distribution found' >&2 ;; *) echo '" + pipErr + "' >&2 ;; esac; exit 1; fi\n"
	return "#!/bin/sh\n" + pipMode + "if [ \"$4\" = info ]; then\ncat <<'EOF'\npyver=" + ver +
		"\nbaseprefix=/usr\nimplementation=cpython\ncertifi=2026.10.19\npip=" + pip + "\ncafile=\nopenssl=x\nEOF\nexit 0\nfi\n" +
		"shift 4\nfor u in \"$@\"; do case $u in https://github.com/) echo \"ok $u\" ;; http*) echo \"" + answer + " $u\" ;; esac; done\n"
}

func installDir(root, ver string) string {
	return filepath.Join(root, "cpython-"+ver+"-macos-aarch64-none")
}

// install makes a real-looking uv install: bin/python3.12 plus python/python3 links beside it.
func (r *rig) install(ver, pip string, trusting bool) string {
	d := installDir(r.pyDir, ver)
	require.NoError(r.t, os.MkdirAll(filepath.Join(d, "bin"), 0o755))
	p := filepath.Join(d, "bin", "python3.12")
	require.NoError(r.t, os.WriteFile(p, []byte(interpreter(ver, pip, trusting)), 0o755))
	require.NoError(r.t, os.Symlink("python3.12", filepath.Join(d, "bin", "python3")))
	require.NoError(r.t, os.Symlink("python3.12", filepath.Join(d, "bin", "python")))
	return p
}

// select_ points uv's launchers and the minor alias at an install, as `uv python install` does.
func (r *rig) selectInstall(ver string) {
	for _, n := range []string{"python", "python3", "python3.12"} {
		_ = os.Remove(filepath.Join(r.launchers, n))
		require.NoError(r.t, os.Symlink(filepath.Join(installDir(r.pyDir, ver), "bin", "python3.12"), filepath.Join(r.launchers, n)))
	}
	alias := filepath.Join(r.pyDir, "cpython-3.12-macos-aarch64-none")
	_ = os.Remove(alias)
	require.NoError(r.t, os.Symlink(installDir(r.pyDir, ver), alias))
}

// shellInstall is the shell that does what a successful upgrade does: install a new patch,
// repoint the launchers and the alias at it. trusting installs one that still trusts the chain.
func (r *rig) shellInstall(ver string, trusting, repoint bool) string {
	d := installDir(r.pyDir, ver)
	staged := filepath.Join(r.root, "stage-"+ver)
	require.NoError(r.t, os.WriteFile(staged, []byte(interpreter(ver, "26.2.2", trusting)), 0o755))
	sh := "mkdir -p " + d + "/bin\ncp " + staged + " " + d + "/bin/python3.12\n" +
		"ln -sf python3.12 " + d + "/bin/python3\nln -sf python3.12 " + d + "/bin/python\n" +
		"echo 'Installed Python " + ver + "'\n"
	if repoint {
		for _, n := range []string{"python", "python3", "python3.12"} {
			sh += "ln -sf " + d + "/bin/python3.12 " + filepath.Join(r.launchers, n) + "\n"
		}
		sh += "rm -f " + r.pyDir + "/cpython-3.12-macos-aarch64-none; ln -s " + d + " " + r.pyDir + "/cpython-3.12-macos-aarch64-none\n"
	}
	return sh
}

type session struct {
	*fixrun.Session
	out *bytes.Buffer
	pr  *prompt.FakePrompter
}

func (r *rig) session(answers ...bool) *session {
	var out bytes.Buffer
	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = answers
	s := &fixrun.Session{Run: exec.NewRealRunner(), Prompt: pr, Out: &out, Stamp: "20261023120000",
		TempDir: r.env.TempDir, Host: platform.Host{OS: "darwin"}}
	return &session{Session: s, out: &out, pr: pr}
}

func (r *rig) fix(minimum string) fixrun.Fix {
	r.t.Helper()
	f := kinds.NewFinding("python", "uv Python")
	f.Requests = []kinds.FixRequest{{Kind: "uvpython", Target: "3.12", Minimum: minimum}}
	fixes, err := New().(kinds.Fixer).Plan(context.Background(), r.env, []kinds.Finding{f})
	require.NoError(r.t, err)
	require.Len(r.t, fixes, 1)
	return fixes[0]
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func link(t *testing.T, p string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(p)
	require.NoError(t, err)
	return got
}

// original sets up 3.12.4 as the selected install and returns its interpreter bytes.
func (r *rig) original() string {
	p := r.install("3.12.4", "26.2.2", true)
	r.selectInstall("3.12.4")
	return read(r.t, p)
}

func TestPlanOnlyRequestedMinorsAndOnlyWithUV(t *testing.T) {
	r := newRig(t)
	k := New().(kinds.Fixer)
	fixes, err := k.Plan(context.Background(), r.env, []kinds.Finding{kinds.NewFinding("python", "x")})
	require.NoError(t, err)
	assert.Empty(t, fixes, "nothing asked for")

	f := kinds.NewFinding("python", "uv Python")
	f.Requests = []kinds.FixRequest{{Kind: "uvtools", Target: "foo"}}
	fixes, _ = k.Plan(context.Background(), r.env, []kinds.Finding{f})
	assert.Empty(t, fixes, "a uvtools request is not this Kind's")

	f.Requests = []kinds.FixRequest{{Kind: "uvpython", Target: "3.12"}}
	r.env.Environ["PATH"] = "/nonexistent"
	fixes, _ = k.Plan(context.Background(), r.env, []kinds.Finding{f})
	assert.Empty(t, fixes, "no uv, nothing to run")
}

func TestUpgradeSuccessKeepsTheNewInstallAndBacksUpTheOriginal(t *testing.T) {
	r := newRig(t)
	orig := r.original()
	r.script(r.shellInstall("3.12.9", false, true))
	r.find(filepath.Join(installDir(r.pyDir, "3.12.9"), "bin", "python3.12"))
	s := r.session(true)

	assert.Equal(t, fixrun.Changed, r.fix("3.12.9").Run(context.Background(), s.Session), s.out.String())

	assert.Equal(t, installDir(r.pyDir, "3.12.9"), link(t, filepath.Join(r.pyDir, "cpython-3.12-macos-aarch64-none")))
	assert.Equal(t, filepath.Join(installDir(r.pyDir, "3.12.9"), "bin", "python3.12"), link(t, filepath.Join(r.launchers, "python3")))
	backups, _ := filepath.Glob(filepath.Join(r.pyDir, ".emudhra-backups", "python-3.12-20261023120000.*"))
	require.Len(t, backups, 1)
	assert.Equal(t, orig, read(t, filepath.Join(backups[0], "installations", "cpython-3.12.4-macos-aarch64-none", "bin", "python3.12")))
	assert.Equal(t, r.pyDir+"\n", read(t, filepath.Join(backups[0], "original-directory")))
	assert.Contains(t, s.out.String(), "selected Python 3.12.9 rejects the compromised chain on all probed Python trust paths")
	assert.Contains(t, s.out.String(), "uv catalogue target: 3.12.9 or newer within Python 3.12")
	assert.Contains(t, s.out.String(), "Installed Python 3.12.9", "uv's own output is echoed")
}

// assertRestored checks the original install bytes, alias and launchers are back.
func assertRestored(t *testing.T, r *rig, orig string) {
	t.Helper()
	assert.Equal(t, orig, read(t, filepath.Join(installDir(r.pyDir, "3.12.4"), "bin", "python3.12")))
	assert.Equal(t, installDir(r.pyDir, "3.12.4"), link(t, filepath.Join(r.pyDir, "cpython-3.12-macos-aarch64-none")))
	for _, n := range []string{"python", "python3", "python3.12"} {
		assert.Equal(t, filepath.Join(installDir(r.pyDir, "3.12.4"), "bin", "python3.12"), link(t, filepath.Join(r.launchers, n)), n)
	}
}

func TestEveryFailureRestoresTheOriginalInstallAndLinks(t *testing.T) {
	cases := []struct {
		name    string
		script  func(r *rig) string
		find    func(r *rig) string
		minimum string
		want    string
	}{
		{"uv fails after changing things", func(r *rig) string {
			return r.shellInstall("3.12.9", false, true) + "echo boom >&2\nexit 1\n"
		}, func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "", "uv python upgrade failed"},
		{"uv cannot find the interpreter", func(r *rig) string { return r.shellInstall("3.12.9", false, true) },
			func(*rig) string { return "" }, "", "could not find the upgraded interpreter"},
		{"new interpreter still trusts the chain", func(r *rig) string { return r.shellInstall("3.12.9", true, true) },
			func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "", "default TLS probe: trusted"},
		{"new interpreter older than the catalogue target", func(r *rig) string { return r.shellInstall("3.12.9", false, true) },
			func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "3.12.11", "selected Python 3.12.9 is older than the available patch 3.12.11"},
		{"minor alias not repointed", func(r *rig) string {
			return strings.Replace(r.shellInstall("3.12.9", false, true), "rm -f "+r.pyDir+"/cpython-3.12-macos-aarch64-none; ln -s "+installDir(r.pyDir, "3.12.9")+" "+r.pyDir+"/cpython-3.12-macos-aarch64-none\n", "", 1)
		}, func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "", "Python minor launcher " + "PYDIR" + "/cpython-3.12-macos-aarch64-none does not select the verified interpreter"},
		{"launchers not repointed but the alias is", func(r *rig) string {
			sh := r.shellInstall("3.12.9", false, true)
			for _, n := range []string{"python", "python3", "python3.12"} {
				sh = strings.Replace(sh, "ln -sf "+installDir(r.pyDir, "3.12.9")+"/bin/python3.12 "+filepath.Join(r.launchers, n)+"\n", "", 1)
			}
			return sh
		}, func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "", "Python launcher " + "LAUNCHERS" + "/python does not select the verified interpreter"},
		{"launchers not repointed", func(r *rig) string { return r.shellInstall("3.12.9", false, false) },
			func(r *rig) string { return installDir(r.pyDir, "3.12.9") + "/bin/python3.12" }, "", "does not select the verified interpreter"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			orig := r.original()
			r.script(c.script(r))
			if f := c.find(r); f != "" {
				r.find(f)
			}
			s := r.session(true)

			assert.Equal(t, fixrun.Failed, r.fix(c.minimum).Run(context.Background(), s.Session))

			assert.Contains(t, s.out.String(), strings.ReplaceAll(strings.ReplaceAll(c.want, "PYDIR", r.pyDir), "LAUNCHERS", r.launchers))
			assert.Contains(t, s.out.String(), "original interpreter contents and links restored; any new patch installation was retained")
			assertRestored(t, r, orig)
			_, err := os.Stat(installDir(r.pyDir, "3.12.9"))
			assert.NoError(t, err, "the new patch install is retained, not deleted")
		})
	}
}

// uv can rebuild the SAME patch in place; the saved copy is the only way back.
func TestAnInPlaceRebuildOfTheSamePatchIsUndone(t *testing.T) {
	r := newRig(t)
	orig := r.original()
	r.script("echo corrupted > " + installDir(r.pyDir, "3.12.4") + "/bin/python3.12\nexit 1")
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("").Run(context.Background(), s.Session))

	assertRestored(t, r, orig)
	_, err := os.Stat(filepath.Join(r.pyDir, ".emudhra-backups"))
	assert.NoError(t, err)
}

func TestNothingChangesWithoutConfirmationOrInADryRun(t *testing.T) {
	for _, dry := range []bool{false, true} {
		r := newRig(t)
		orig := r.original()
		r.script("touch " + filepath.Join(r.root, "upgraded") + "\n")
		s := r.session(false)
		s.DryRun = dry

		assert.Equal(t, fixrun.Skipped, r.fix("").Run(context.Background(), s.Session), "dry=%v", dry)

		_, err := os.Stat(filepath.Join(r.root, "upgraded"))
		assert.True(t, os.IsNotExist(err), "uv must not run (dry=%v)", dry)
		_, err = os.Stat(filepath.Join(r.pyDir, ".emudhra-backups"))
		assert.True(t, os.IsNotExist(err), "no backup directory either (dry=%v)", dry)
		assertRestored(t, r, orig)
		if dry {
			assert.Contains(t, s.out.String(), "[dry-run] would back up complete interpreter installations")
			assert.Zero(t, s.pr.ConfirmCalled, "a dry run does not ask")
		}
	}
}

func TestASymlinkedPatchInstallationIsRefusedBeforeAnything(t *testing.T) {
	r := newRig(t)
	r.original()
	real := filepath.Join(r.root, "elsewhere")
	require.NoError(t, os.Rename(installDir(r.pyDir, "3.12.4"), real))
	require.NoError(t, os.Symlink(real, installDir(r.pyDir, "3.12.4")))
	r.script("touch " + filepath.Join(r.root, "upgraded"))
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("").Run(context.Background(), s.Session))

	assert.Contains(t, s.out.String(), "symlinked patch installation is not supported: "+installDir(r.pyDir, "3.12.4"))
	_, err := os.Stat(filepath.Join(r.root, "upgraded"))
	assert.True(t, os.IsNotExist(err))
	assert.Zero(t, s.pr.ConfirmCalled)
}

func TestAnOldUVIsNotUsedToDownload(t *testing.T) {
	r := newRig(t)
	r.original()
	uv := filepath.Join(r.bin, "uv")
	b := read(t, uv)
	require.NoError(t, os.WriteFile(uv, []byte(strings.Replace(b, "uv 0.13.4", "uv 0.9.0", 1)), 0o755))
	r.script("touch " + filepath.Join(r.root, "upgraded"))
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("").Run(context.Background(), s.Session))

	assert.Contains(t, s.out.String(), "cannot safely perform these downloads")
	_, err := os.Stat(filepath.Join(r.root, "upgraded"))
	assert.True(t, os.IsNotExist(err))
}

func TestAMissingLauncherDirectoryFailsBeforeAnyChange(t *testing.T) {
	r := newRig(t)
	r.original()
	require.NoError(t, os.RemoveAll(r.launchers))
	r.script("touch " + filepath.Join(r.root, "upgraded"))
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("").Run(context.Background(), s.Session))

	assert.Contains(t, s.out.String(), "cannot locate uv's Python executable directory")
	_, err := os.Stat(filepath.Join(r.root, "upgraded"))
	assert.True(t, os.IsNotExist(err))
}

func TestAnInsecureBackupRootStopsTheUpgrade(t *testing.T) {
	r := newRig(t)
	r.original()
	require.NoError(t, os.MkdirAll(filepath.Join(r.pyDir, ".emudhra-backups"), 0o777))
	require.NoError(t, os.Chmod(filepath.Join(r.pyDir, ".emudhra-backups"), 0o777))
	r.script("touch " + filepath.Join(r.root, "upgraded"))
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("").Run(context.Background(), s.Session))

	assert.Contains(t, s.out.String(), "cannot prepare Python backups on the installation filesystem")
	_, err := os.Stat(filepath.Join(r.root, "upgraded"))
	assert.True(t, os.IsNotExist(err))
}

func TestApplicabilityIsMacOSAndLinuxOnly(t *testing.T) {
	k := New()
	assert.True(t, k.Applicable(platform.Host{OS: "darwin"}).Applies)
	assert.True(t, k.Applicable(platform.Host{OS: "linux"}).Applies)
	assert.False(t, k.Applicable(platform.Host{OS: "windows"}).Applies)
	assert.Equal(t, kinds.FixUVPython, k.(kinds.Fixer).FixOrder())
}

// A launcher that was not a link before the upgrade is not required to be one afterwards.
func TestLaunchersThatWereNotLinksAreNotRequired(t *testing.T) {
	r := newRig(t)
	r.original()
	require.NoError(t, os.Remove(filepath.Join(r.launchers, "python")))
	script := r.shellInstall("3.12.9", false, true) + "rm -f " + filepath.Join(r.launchers, "python") + "\n"
	r.script(script)
	r.find(filepath.Join(installDir(r.pyDir, "3.12.9"), "bin", "python3.12"))
	s := r.session(true)

	assert.Equal(t, fixrun.Changed, r.fix("").Run(context.Background(), s.Session), s.out.String())
}

// Only the tail of uv's output is echoed.
func TestOnlyTheLastSixLinesOfUVOutputAreEchoed(t *testing.T) {
	r := newRig(t)
	r.original()
	r.script("for i in 1 2 3 4 5 6 7 8 9 10; do echo uvline$i; done\nexit 1")
	s := r.session(true)

	r.fix("").Run(context.Background(), s.Session)

	out := s.out.String()
	assert.NotContains(t, out, "uvline4\n")
	assert.Contains(t, out, "\n      uvline5\n")
	assert.Contains(t, out, "\n      uvline10\n")
}
