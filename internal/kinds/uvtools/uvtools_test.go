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

package uvtools

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

// rig is a real layout with a stub uv whose `tool upgrade`, `pip check` and `tool list` the test
// scripts, so the fixer's backups, verification and rollback act on real files.
type rig struct {
	t               *testing.T
	root, home, bin string
	toolsDir, pyDir string
	binDir          string
	env             *kinds.Env
	upgradeArgsFile string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	r := &rig{t: t, root: root, home: filepath.Join(root, "home"), bin: filepath.Join(root, "bin"),
		toolsDir: filepath.Join(root, "tools"), pyDir: filepath.Join(root, "uvpython"), binDir: filepath.Join(root, "toolbin"),
		upgradeArgsFile: filepath.Join(root, "upgrade-args")}
	for _, d := range []string{r.home, r.bin, r.toolsDir, r.pyDir, r.binDir} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	uv := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *--version*) echo 'uv 0.13.4' ;;\n" +
		"  *\"tool dir --bin\"*) echo " + r.binDir + " ;;\n" +
		"  *\"tool dir\"*) echo " + r.toolsDir + " ;;\n" +
		"  *\"python dir\"*) echo " + r.pyDir + " ;;\n" +
		"  *\"python find\"*) cat " + filepath.Join(root, "find.txt") + " || exit 1 ;;\n" +
		"  *\"tool list\"*) cat " + filepath.Join(root, "list.txt") + " || exit 1 ;;\n" +
		"  *\"tool upgrade\"*) echo \"$@\" > " + r.upgradeArgsFile + "; sh " + filepath.Join(root, "upgrade.sh") + " ; exit $? ;;\n" +
		"  *\"pip check\"*) sh " + filepath.Join(root, "check.sh") + " ; exit $? ;;\n" +
		"esac\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.bin, "uv"), []byte(uv), 0o755))
	r.write("upgrade.sh", "exit 0")
	r.write("check.sh", "exit 0")
	r.env = testutil.NewTestEnvT(t)
	r.env.Run = exec.NewRealRunner()
	r.env.Environ = map[string]string{"HOME": r.home, "PATH": r.bin + ":/usr/bin:/bin"}
	return r
}

func (r *rig) write(name, body string) {
	require.NoError(r.t, os.WriteFile(filepath.Join(r.root, name), []byte(body+"\n"), 0o644))
}

// interpreter is a stub python: its metadata, and every probed URL answered as the compromised
// chain being rejected or (trusting) accepted, except the control.
func interpreter(base, ver string, trusting bool) string {
	answer, pipErr := "certerr", "SSLError CERTIFICATE_VERIFY_FAILED"
	if trusting {
		answer, pipErr = "ok", "ERROR: No matching distribution found"
	}
	pipMode := "if [ \"$3\" = -m ]; then case \"$*\" in *github.com*) echo 'ERROR: No matching distribution found' >&2 ;; *) echo '" + pipErr + "' >&2 ;; esac; exit 1; fi\n"
	return "#!/bin/sh\n" + pipMode + "if [ \"$4\" = info ]; then\ncat <<'EOF'\npyver=" + ver +
		"\nbaseprefix=" + base + "\nimplementation=cpython\ncertifi=2026.10.19\npip=26.2.2\ncafile=\nopenssl=x\nEOF\nexit 0\nfi\n" +
		"shift 4\nfor u in \"$@\"; do case $u in https://github.com/) echo \"ok $u\" ;; http*) echo \"" + answer + " $u\" ;; esac; done\n"
}

// managed makes a uv managed install and returns its directory (the tool's base prefix).
func (r *rig) managed(ver string) string {
	d := filepath.Join(r.pyDir, "cpython-"+ver+"-macos-aarch64-none")
	require.NoError(r.t, os.MkdirAll(filepath.Join(d, "bin"), 0o755))
	require.NoError(r.t, os.WriteFile(filepath.Join(d, "bin", "python3.12"), []byte(interpreter(d, ver, false)), 0o755))
	r.write("find.txt", filepath.Join(d, "bin", "python3.12"))
	return d
}

// tool makes a uv tool environment named name with the interpreter base/ver, one entry point
// linked into the tool bin directory, and a `uv tool list` that reports it.
func (r *rig) tool(name, base, ver string, trusting bool) (dir, entry string) {
	dir = filepath.Join(r.toolsDir, name)
	require.NoError(r.t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	require.NoError(r.t, os.WriteFile(filepath.Join(dir, "uv-receipt.toml"), []byte("[tool]\n"), 0o644))
	require.NoError(r.t, os.WriteFile(filepath.Join(dir, "bin", "python"), []byte(interpreter(base, ver, trusting)), 0o755))
	require.NoError(r.t, os.WriteFile(filepath.Join(dir, "bin", name), []byte("#!/bin/sh\necho "+name+"\n"), 0o755))
	entry = filepath.Join(r.binDir, name)
	require.NoError(r.t, os.Symlink(filepath.Join(dir, "bin", name), entry))
	r.write("list.txt", name+" v1.0\n- "+name+" ("+entry+")")
	return dir, entry
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

func (r *rig) fix(name string) fixrun.Fix {
	r.t.Helper()
	f := kinds.NewFinding("python", "uv tool")
	f.Requests = []kinds.FixRequest{{Kind: "uvtools", Target: name}}
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

func (r *rig) untouched() bool {
	_, err := os.Stat(r.upgradeArgsFile)
	return os.IsNotExist(err)
}

// start is the usual starting point: a tool on a managed 3.12.4 that still trusts the chain.
func (r *rig) start() (dir, entry, orig string) {
	base := r.managed("3.12.4")
	dir, entry = r.tool("ruff", base, "3.12.4", true)
	return dir, entry, read(r.t, filepath.Join(dir, "bin", "python"))
}

// upgradeTo is what a successful `uv tool upgrade` leaves: a Python that rejects the chain.
func (r *rig) upgradeTo(dir, base string) {
	staged := filepath.Join(r.root, "newpython")
	require.NoError(r.t, os.WriteFile(staged, []byte(interpreter(base, "3.12.4", false)), 0o755))
	r.write("upgrade.sh", "echo 'Updated ruff'\ncp "+staged+" "+filepath.Join(dir, "bin", "python"))
}

func TestPlanOnlyRequestedToolsAndOnlyWithUV(t *testing.T) {
	r := newRig(t)
	k := New().(kinds.Fixer)
	fixes, err := k.Plan(context.Background(), r.env, []kinds.Finding{kinds.NewFinding("python", "x")})
	require.NoError(t, err)
	assert.Empty(t, fixes)

	f := kinds.NewFinding("python", "uv Python")
	f.Requests = []kinds.FixRequest{{Kind: "uvpython", Target: "3.12"}}
	fixes, _ = k.Plan(context.Background(), r.env, []kinds.Finding{f})
	assert.Empty(t, fixes, "a uvpython request is not this Kind's")

	f.Requests = []kinds.FixRequest{{Kind: "uvtools", Target: "ruff"}, {Kind: "uvtools", Target: "black"}}
	fixes, _ = k.Plan(context.Background(), r.env, []kinds.Finding{f})
	assert.Len(t, fixes, 2)
	assert.Equal(t, "ruff", fixes[0].Target())

	r.env.Environ["PATH"] = "/nonexistent"
	fixes, _ = k.Plan(context.Background(), r.env, []kinds.Finding{f})
	assert.Empty(t, fixes, "no uv, nothing to run")
}

func TestUpgradeSuccessKeepsTheNewEnvironmentAndBacksUpTheOriginal(t *testing.T) {
	r := newRig(t)
	dir, entry, orig := r.start()
	r.upgradeTo(dir, r.managed("3.12.4"))
	s := r.session(true)

	assert.Equal(t, fixrun.Changed, r.fix("ruff").Run(context.Background(), s.Session), s.out.String())

	assert.NotEqual(t, orig, read(t, filepath.Join(dir, "bin", "python")), "the upgraded environment stays")
	backups, _ := filepath.Glob(r.toolsDir + ".emudhra-backups/tool-ruff-20261023120000.*")
	require.Len(t, backups, 1, "the backup is a sibling of the tools directory, never inside it")
	assert.Equal(t, orig, read(t, filepath.Join(backups[0], "environment", "bin", "python")))
	l, err := os.Readlink(filepath.Join(backups[0], "bin-links", "ruff"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "bin", "ruff"), l)
	assert.Equal(t, dir+"\n", read(t, filepath.Join(backups[0], "original-directory")))
	_, err = os.Lstat(entry)
	assert.NoError(t, err)
	assert.Contains(t, s.out.String(), "ruff dependencies are consistent; its Python trust paths reject the compromised chain")
	assert.Contains(t, s.out.String(), "Updated ruff", "uv's own output is echoed")
	assert.Contains(t, s.out.String(), "uv tool upgrade ruff --python "+filepath.Join(r.pyDir, "cpython-3.12.4-macos-aarch64-none", "bin", "python3.12")+" --no-python-downloads")
	args := read(t, r.upgradeArgsFile)
	assert.Contains(t, args, "tool upgrade ruff --python "+filepath.Join(r.pyDir, "cpython-3.12.4-macos-aarch64-none", "bin", "python3.12")+" --no-python-downloads")
}

func TestAToolOnAnExternalPythonIsRebuiltOnThatSameInterpreter(t *testing.T) {
	r := newRig(t)
	ext := filepath.Join(r.root, "ext")
	require.NoError(t, os.MkdirAll(filepath.Join(ext, "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ext, "bin", "python3"), []byte("#!/bin/sh\n"), 0o755))
	dir, _ := r.tool("ruff", ext, "3.12.4", true)
	r.upgradeTo(dir, ext)
	s := r.session(true)

	assert.Equal(t, fixrun.Changed, r.fix("ruff").Run(context.Background(), s.Session), s.out.String())

	assert.Contains(t, read(t, r.upgradeArgsFile), "--python "+filepath.Join(ext, "bin", "python3")+" --no-python-downloads", "the exact external interpreter, not a uv one")
}

func TestEveryFailureRestoresTheEnvironmentAndTheLinks(t *testing.T) {
	cases := []struct {
		name, upgrade, check, want string
	}{
		{"uv fails after changing things", "rm -f {BIN}/ruff\necho 'boom' >&2\nexit 1", "exit 0", "uv tool upgrade failed"},
		{"the upgraded Python still trusts the chain", "echo ok", "exit 0", "default TLS probe: trusted"},
		{"dependencies are inconsistent", "cp {STAGED} {DIR}/bin/python", "echo 'broken' >&2; exit 1", "dependency verification failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			dir, entry, orig := r.start()
			staged := filepath.Join(r.root, "newpython")
			require.NoError(t, os.WriteFile(staged, []byte(interpreter("/x", "3.12.4", false)), 0o755))
			up := strings.NewReplacer("{BIN}", r.binDir, "{DIR}", dir, "{STAGED}", staged).Replace(c.upgrade)
			// corrupt the environment too, so a missing restore is visible
			r.write("upgrade.sh", "echo corrupt > "+filepath.Join(dir, "bin", "ruff")+"\n"+up)
			r.write("check.sh", c.check)
			s := r.session(true)

			assert.Equal(t, fixrun.Failed, r.fix("ruff").Run(context.Background(), s.Session))

			assert.Contains(t, s.out.String(), c.want)
			assert.Contains(t, s.out.String(), "original tool environment and links restored")
			assert.Equal(t, orig, read(t, filepath.Join(dir, "bin", "python")))
			assert.Equal(t, "#!/bin/sh\necho ruff\n", read(t, filepath.Join(dir, "bin", "ruff")), "the original entry point script is back")
			l, err := os.Readlink(entry)
			require.NoError(t, err, "the executable link is back")
			assert.Equal(t, filepath.Join(dir, "bin", "ruff"), l)
			failed, _ := filepath.Glob(r.toolsDir + ".emudhra-backups/tool-ruff-*/failed-environment")
			assert.Len(t, failed, 1, "the failed environment is preserved, not deleted")
		})
	}
}

func TestNothingChangesWithoutConfirmationOrInADryRun(t *testing.T) {
	for _, dry := range []bool{false, true} {
		r := newRig(t)
		dir, _, orig := r.start()
		s := r.session(false)
		s.DryRun = dry

		assert.Equal(t, fixrun.Skipped, r.fix("ruff").Run(context.Background(), s.Session), "dry=%v", dry)

		assert.True(t, r.untouched(), "uv must not run (dry=%v)", dry)
		_, err := os.Stat(r.toolsDir + ".emudhra-backups")
		assert.True(t, os.IsNotExist(err), "no backup directory either (dry=%v)", dry)
		assert.Equal(t, orig, read(t, filepath.Join(dir, "bin", "python")))
		if dry {
			assert.Contains(t, s.out.String(), "[dry-run] would back up the full environment and its executable links")
			assert.Zero(t, s.pr.ConfirmCalled)
		}
	}
}

// Everything the fixer checks before it may touch anything: each must stop with nothing run.
func TestPreconditionsStopTheFixBeforeUVRuns(t *testing.T) {
	cases := []struct {
		name   string
		name_  string
		setup  func(r *rig, dir, entry string)
		want   string
		answer bool
	}{
		{"unsafe tool name", "../evil", func(*rig, string, string) {}, "unsupported tool name", true},
		{"tool name with a leading dash", "-x", func(*rig, string, string) {}, "unsupported tool name", true},
		{"tool environment missing", "ghost", func(*rig, string, string) {}, "tool environment is missing, symlinked, or has no uv receipt", true},
		{"no receipt", "ruff", func(r *rig, dir, _ string) { require.NoError(t, os.Remove(filepath.Join(dir, "uv-receipt.toml"))) },
			"tool environment is missing, symlinked, or has no uv receipt", true},
		{"environment is a symlink", "ruff", func(r *rig, dir, _ string) {
			real := filepath.Join(r.root, "elsewhere")
			require.NoError(t, os.Rename(dir, real))
			require.NoError(t, os.Symlink(real, dir))
		}, "tool environment is missing, symlinked, or has no uv receipt", true},
		{"python gives no metadata", "ruff", func(r *rig, dir, _ string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "python"), []byte("#!/bin/sh\nexit 1\n"), 0o755))
		}, "cannot preserve this tool's Python version and implementation automatically", true},
		{"not cpython", "ruff", func(r *rig, dir, _ string) {
			b := read(t, filepath.Join(dir, "bin", "python"))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "python"), []byte(strings.Replace(b, "implementation=cpython", "implementation=pypy", 1)), 0o755))
		}, "cannot preserve this tool's Python version and implementation automatically", true},
		{"no version reported", "ruff", func(r *rig, dir, _ string) {
			b := read(t, filepath.Join(dir, "bin", "python"))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "python"), []byte(strings.Replace(b, "pyver=3.12.4", "pyver=", 1)), 0o755))
		}, "cannot preserve this tool's Python version and implementation automatically", true},
		{"no base prefix reported", "ruff", func(r *rig, dir, _ string) {
			b := read(t, filepath.Join(dir, "bin", "python"))
			i := strings.Index(b, "baseprefix=")
			j := strings.Index(b[i:], "\n")
			require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "python"), []byte(b[:i]+"baseprefix="+b[i+j:]), 0o755))
		}, "cannot preserve this tool's Python version and implementation automatically", true},
		{"no usable interpreter", "ruff", func(r *rig, _, _ string) { r.write("find.txt", "/does/not/exist") },
			"cannot locate a usable Python 3.12 interpreter", true},
		{"interpreter not executable", "ruff", func(r *rig, _, _ string) {
			p := filepath.Join(r.pyDir, "cpython-3.12.4-macos-aarch64-none", "bin", "python3.12")
			require.NoError(t, os.Chmod(p, 0o644))
		}, "cannot locate a usable Python 3.12 interpreter", true},
		{"uv cannot list the entry points", "ruff", func(r *rig, _, _ string) { require.NoError(t, os.Remove(filepath.Join(r.root, "list.txt"))) },
			"recorded executable paths differ from the current tool bin directory, or an entry point belongs to another tool", true},
		{"entry point recorded outside the tool bin directory", "ruff", func(r *rig, _, _ string) {
			r.write("list.txt", "ruff v1.0\n- ruff ("+filepath.Join(r.root, "other", "ruff")+")")
			require.NoError(t, os.MkdirAll(filepath.Join(r.root, "other"), 0o755))
		}, "recorded executable paths differ", true},
		{"entry point belongs to another tool", "ruff", func(r *rig, _, entry string) {
			require.NoError(t, os.Remove(entry))
			require.NoError(t, os.Symlink(filepath.Join(r.root, "stranger"), entry))
		}, "recorded executable paths differ", true},
		{"entry point is a plain file", "ruff", func(r *rig, _, entry string) {
			require.NoError(t, os.Remove(entry))
			require.NoError(t, os.WriteFile(entry, []byte("x"), 0o755))
		}, "recorded executable paths differ", true},
		{"tool missing from uv's listing", "ruff", func(r *rig, _, _ string) { r.write("list.txt", "black v1.0\n- black (/x/black)") },
			"recorded executable paths differ", true},
		{"tool bin directory missing", "ruff", func(r *rig, _, _ string) { require.NoError(t, os.RemoveAll(r.binDir)) },
			"cannot locate uv's tool executable directory", true},
		{"insecure backup root", "ruff", func(r *rig, _, _ string) {
			require.NoError(t, os.MkdirAll(r.toolsDir+".emudhra-backups", 0o777))
			require.NoError(t, os.Chmod(r.toolsDir+".emudhra-backups", 0o777))
		}, "cannot prepare tool backups on the installation filesystem", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			dir, entry, _ := r.start()
			c.setup(r, dir, entry)
			s := r.session(c.answer)
			name := c.name_
			if name == "" {
				name = "ruff"
			}

			assert.Equal(t, fixrun.Failed, r.fixNamed(name).Run(context.Background(), s.Session), s.out.String())

			assert.Contains(t, s.out.String(), c.want)
			assert.True(t, r.untouched(), "uv must not have run")
		})
	}
}

func (r *rig) fixNamed(name string) fixrun.Fix { return r.fix(name) }

func TestAnOldUVIsNotUsedToDownload(t *testing.T) {
	r := newRig(t)
	r.start()
	uv := filepath.Join(r.bin, "uv")
	require.NoError(t, os.WriteFile(uv, []byte(strings.Replace(read(t, uv), "uv 0.13.4", "uv 0.9.0", 1)), 0o755))
	s := r.session(true)

	assert.Equal(t, fixrun.Failed, r.fix("ruff").Run(context.Background(), s.Session))

	assert.Contains(t, s.out.String(), "cannot safely perform these downloads")
	assert.True(t, r.untouched())
}

func TestApplicabilityIsMacOSAndLinuxOnly(t *testing.T) {
	k := New()
	assert.True(t, k.Applicable(platform.Host{OS: "darwin"}).Applies)
	assert.True(t, k.Applicable(platform.Host{OS: "linux"}).Applies)
	assert.False(t, k.Applicable(platform.Host{OS: "windows"}).Applies)
	assert.Equal(t, kinds.FixUVTools, k.(kinds.Fixer).FixOrder())
}

// Only the tail of uv's output is echoed.
func TestOnlyTheLastSixLinesOfUVOutputAreEchoed(t *testing.T) {
	r := newRig(t)
	r.start()
	r.write("upgrade.sh", "for i in 1 2 3 4 5 6 7 8 9 10; do echo uvline$i; done\nexit 1")
	s := r.session(true)

	r.fix("ruff").Run(context.Background(), s.Session)

	out := s.out.String()
	assert.NotContains(t, out, "uvline4\n")
	assert.Contains(t, out, "\n      uvline5\n")
	assert.Contains(t, out, "\n      uvline10\n")
}
