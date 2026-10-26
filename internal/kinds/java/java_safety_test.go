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

package java

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/testutil"
)

// The two subjects the advisory says to distrust, and others that must never be touched.
const (
	subjAAA    = "AAA Certificate Services"
	subjEmSign = "emSign ECC Root CA - G3"
)

// keytoolStub is a keytool that works on a plain-text keystore with one
// "alias|subject" line per entry, implementing exactly the commands the fixer
// uses: -list, -list -v [-alias A], -delete -alias A. It runs for real, through the
// real runner, so entry counts and deletions are truthful. (This is how the script's
// own test works: a real keytool on a throwaway JDK copy.)
const keytoolStub = `#!/bin/sh
store=""; alias=""; verbose=0; delete=0; list=0
while [ $# -gt 0 ]; do
  case "$1" in
    -keystore) store="$2"; shift ;;
    -alias) alias="$2"; shift ;;
    -delete) delete=1 ;;
    -list) list=1 ;;
    -v) verbose=1 ;;
  esac
  shift
done
[ -f "$store" ] || { echo "keytool error: Keystore file does not exist: $store" >&2; exit 1; }
if [ "$delete" = 1 ]; then
  [ -n "$KEYTOOL_FAIL_DELETE" ] && { echo "keytool error: cannot delete" >&2; exit 1; }
  grep -q "^$alias|" "$store" || { echo "keytool error: Alias <$alias> does not exist" >&2; exit 1; }
  if [ -n "$KEYTOOL_DELETE_NOTHING" ]; then exit 0; fi
  # KEYTOOL_DELETE_WRONG: delete an innocent entry instead, so the COUNT drops by the right
  # amount but a root stays. KEYTOOL_DELETE_EXTRA: also delete an innocent entry, so the roots
  # go but the count drops by too much.
  if [ -n "$KEYTOOL_DELETE_WRONG" ]; then grep -v "^isrg|" "$store" > "$store.new"; mv "$store.new" "$store"; exit 0; fi
  if [ -n "$KEYTOOL_DELETE_EXTRA" ]; then grep -v -e "^$alias|" -e "^lets|" "$store" > "$store.new"; mv "$store.new" "$store"; exit 0; fi
  grep -v "^$alias|" "$store" > "$store.new"; mv "$store.new" "$store"; exit 0
fi
if [ "$list" = 1 ]; then
  while IFS='|' read -r a s; do
    [ -n "$a" ] || continue
    [ -z "$alias" ] || [ "$alias" = "$a" ] || continue
    if [ "$verbose" = 1 ]; then
      echo "Alias name: $a"; echo "Entry type: trustedCertEntry"; echo "Owner: CN=$s, O=Test, C=US"; echo
    else
      echo "$a, Jan 1, 2020, trustedCertEntry,"
    fi
  done < "$store"
fi
`

// javaStub plays the compiled EmudhraProbe. A real JDK trusts the chain exactly while
// its truststore holds one of the two roots, so the stub answers from the keystore it is
// given (-Djavax.net.ssl.trustStore=, else the JDK's own cacerts) and not from a canned
// answer: delete the roots and the verdict changes, as it does for real.
//
// Test knobs: PROBE_FORCE=trusted|rejected|inconclusive overrides the answer for the
// patched copy (PROBE_FORCE_PATCHED) or the live JDK (PROBE_FORCE_LIVE).
const javaStub = `#!/bin/sh
store=""
mode=live
for a in "$@"; do
  case "$a" in -Djavax.net.ssl.trustStore=*) store="${a#-Djavax.net.ssl.trustStore=}"; mode=patched ;; esac
done
[ -n "$store" ] || store="$JDK_CACERTS"
force=""
if [ "$mode" = patched ]; then force="$PROBE_FORCE_PATCHED"; else force="$PROBE_FORCE_LIVE"; fi
verdict=rejected
if [ -n "$force" ]; then verdict="$force"
elif grep -q -e '|AAA Certificate Services$' -e '|emSign ECC Root CA - G3$' "$store" 2>/dev/null; then verdict=trusted; fi
c=https://github.com/; a=https://dv-g3b-emudhra.we-have-a-problem.com/; b=https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
case "$verdict" in
  trusted) printf 'ok %s\nok %s\nok %s\n' "$c" "$a" "$b" ;;
  rejected) printf 'ok %s\ncerterr %s\ncerterr %s\n' "$c" "$a" "$b" ;;
  inconclusive) printf 'ok %s\nerr %s\nerr %s\n' "$c" "$a" "$b" ;;
esac
`

const javacStub = `#!/bin/sh
exit 0
`

// jdk is a throwaway JDK: stub tools and a text cacerts. The user answers YES, so a
// confirmation can never hide a missing guard in the code under test.
type jdk struct {
	t       *testing.T
	home    string
	cacerts string
	priv    *privilege.FakeEscalator
	out     *bytes.Buffer
	session *fixrun.Session
	env     *kinds.Env
}

type jdkOpts struct {
	entries      []string // alias|subject lines
	dryRun       bool
	declined     bool
	noSudo       bool
	forcePatched string // trusted|rejected|inconclusive, "" = follow the keystore
	forceLive    string
	failOn       func(string) error
	noJavac      bool
	envVars      map[string]string
}

func defaultEntries() []string {
	return []string{"aaa_root|" + subjAAA, "emsign_root|" + subjEmSign, "digicert|DigiCert Global Root G2", "isrg|ISRG Root X1", "lets|Let's Encrypt R3"}
}

func newJDK(t *testing.T, o jdkOpts) *jdk {
	t.Helper()
	// Resolve the temp directory first: the audit reports a JDK by its resolved path (the
	// script's cd -P), and on macOS t.TempDir() sits under the /var -> /private/var symlink.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	home := filepath.Join(dir, "jdk")
	bin := filepath.Join(home, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "lib", "security"), 0o755))
	tools := map[string]string{"keytool": keytoolStub, "java": javaStub}
	if !o.noJavac {
		tools["javac"] = javacStub
	}
	for n, body := range tools {
		require.NoError(t, os.WriteFile(filepath.Join(bin, n), []byte(body), 0o755))
	}
	cacerts := filepath.Join(home, "lib", "security", "cacerts")
	entries := o.entries
	if entries == nil {
		entries = defaultEntries()
	}
	require.NoError(t, os.WriteFile(cacerts, []byte(strings.Join(entries, "\n")+"\n"), 0o644))

	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{!o.declined}
	priv := privilege.NewFakeEscalator()
	priv.IsRootVal = !o.noSudo
	priv.HasSudoVal = !o.noSudo
	if o.noSudo {
		priv.NeedsMap = map[string]bool{cacerts: true}
	}
	priv.FailOn = o.failOn

	env := testutil.NewTestEnvT(t)
	env.Run = exec.NewRealRunner()
	env.Environ = map[string]string{"HOME": dir, "PATH": bin, "EMUDHRA_JAVA_HOMES": home}
	for k, v := range o.envVars {
		env.Environ[k] = v
	}
	// the real runner passes the process environment to the stubs, which read these
	t.Setenv("JDK_CACERTS", cacerts)
	t.Setenv("PROBE_FORCE_PATCHED", o.forcePatched)
	t.Setenv("PROBE_FORCE_LIVE", o.forceLive)

	j := &jdk{t: t, home: home, cacerts: cacerts, priv: priv, out: &bytes.Buffer{}, env: env}
	j.session = &fixrun.Session{
		Run: env.Run, DryRun: o.dryRun, TempDir: t.TempDir(), Stamp: "20261023120000",
		Prompt: pr, Priv: priv, Out: j.out,
	}
	return j
}

// plan runs the real sequence: Audit, then Plan, and returns the fixes.
func (j *jdk) plan() []fixrun.Fix {
	j.t.Helper()
	k := New().(*Kind)
	findings, err := k.Audit(context.Background(), j.env)
	require.NoError(j.t, err)
	fixes, err := k.Plan(context.Background(), j.env, findings)
	require.NoError(j.t, err)
	return fixes
}

func (j *jdk) fix() fixrun.Fix {
	j.t.Helper()
	fixes := j.plan()
	require.Len(j.t, fixes, 1, "expected one fix for this JDK; output: %s", j.out.String())
	return fixes[0]
}

func (j *jdk) run() fixrun.Outcome { return j.fix().Run(context.Background(), j.session) }

func (j *jdk) aliases() []string {
	j.t.Helper()
	b, err := os.ReadFile(j.cacerts)
	require.NoError(j.t, err)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, strings.SplitN(l, "|", 2)[0])
		}
	}
	return out
}

func (j *jdk) ran(prefix string) bool {
	for _, c := range j.priv.Commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// restoreRecorded: "cp -p CACERTS.pre-emudhra-STAMP CACERTS".
func (j *jdk) restoreRecorded() bool {
	return j.ran("cp -p "+j.cacerts+".pre-emudhra-") && func() bool {
		for _, c := range j.priv.Commands {
			if strings.HasPrefix(c, "cp -p "+j.cacerts+".pre-emudhra-") && strings.HasSuffix(c, " "+j.cacerts) {
				return true
			}
		}
		return false
	}()
}

// Smoke test of the harness itself: if this fails, nothing built on it can be trusted.
func TestHarness_AuditPlansOneFixAndASuccessfulRunDeletesExactlyTheTwoRoots(t *testing.T) {
	j := newJDK(t, jdkOpts{}) // the stub trusts the chain while the roots are in the keystore
	out := j.run()
	require.Equal(t, fixrun.Changed, out, j.out.String())
	assert.ElementsMatch(t, []string{"digicert", "isrg", "lets"}, j.aliases(), "the two roots are gone and nothing else")
}

// ---- the behaviours of fix_java_store ---------------------------------------------

func TestJavaFix_AnsweringNoChangesNothing(t *testing.T) {
	j := newJDK(t, jdkOpts{declined: true})
	before := j.aliases()
	assert.Equal(t, fixrun.Skipped, j.run())
	assert.Equal(t, before, j.aliases(), "the real cacerts must be untouched")
	assert.Empty(t, j.priv.Commands, "no backup and no install")
}

func TestJavaFix_DryRunChangesNothingAndShowsTheCommands(t *testing.T) {
	j := newJDK(t, jdkOpts{dryRun: true})
	before := j.aliases()
	assert.Equal(t, fixrun.Skipped, j.run())
	assert.Equal(t, before, j.aliases())
	assert.Empty(t, j.priv.Commands, "a dry run runs no privileged command")
	assert.Contains(t, j.out.String(), "[dry-run] would back up to "+j.cacerts+".pre-emudhra-20261023120000")
	assert.Contains(t, j.out.String(), "test on a copy: this JDK rejects the compromised chain", "and it still verified on a copy")
}

func TestJavaFix_SuccessBacksUpDeletesExactlyTheTwoRootsAndVerifies(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	require.Equal(t, fixrun.Changed, j.run(), j.out.String())
	assert.ElementsMatch(t, []string{"digicert", "isrg", "lets"}, j.aliases())
	assert.True(t, j.ran("cp -p "+j.cacerts+" "+j.cacerts+".pre-emudhra-20261023120000"), "backed up first: %q", j.priv.Commands)
	assert.True(t, j.ran("cp "), "and the patched store installed: %q", j.priv.Commands)
}

func TestJavaFix_OnlyTheTwoRootsAreEverDeleted(t *testing.T) {
	// aliases differ by vendor, so the match is on the SUBJECT: an alias that merely
	// sounds like a root, or a different emSign root, must stay.
	j := newJDK(t, jdkOpts{entries: []string{
		"aaa_root|" + subjAAA, "emsign_g3|" + subjEmSign,
		"emsign_g1|emSign Root CA - G1", "emsign_ecc_g3_lookalike|emSign ECC Root CA - G4", "comodo_other|COMODO ECC Certification Authority",
	}})
	require.Equal(t, fixrun.Changed, j.run(), j.out.String())
	assert.ElementsMatch(t, []string{"emsign_g1", "emsign_ecc_g3_lookalike", "comodo_other"}, j.aliases())
}

func TestJavaFix_NoRootsMeansNothingToDo(t *testing.T) {
	j := newJDK(t, jdkOpts{entries: []string{"digicert|DigiCert Global Root G2"}})
	assert.Empty(t, j.plan(), "a store without the roots is not planned (the probe does not trust the chain)")

	// and if it is run anyway it says so and changes nothing
	j2 := newJDK(t, jdkOpts{entries: []string{"digicert|DigiCert Global Root G2"}, forceLive: "trusted"})
	fixes := j2.plan()
	require.Len(t, fixes, 1)
	assert.Equal(t, fixrun.Skipped, fixes[0].Run(context.Background(), j2.session))
	assert.Contains(t, j2.out.String(), "none of the roots are in")
	assert.Empty(t, j2.priv.Commands)
}

func TestJavaFix_ADeleteThatRemovesNothingIsCaughtOnTheCopy(t *testing.T) {
	// keytool exits 0 but the entries are still there: the script's count check catches it.
	j := newJDK(t, jdkOpts{envVars: map[string]string{"KEYTOOL_DELETE_NOTHING": "1"}})
	t.Setenv("KEYTOOL_DELETE_NOTHING", "1")
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Equal(t, before, j.aliases(), "nothing may be applied")
	assert.Empty(t, j.priv.Commands)
	assert.Contains(t, j.out.String(), "not applying")
}

func TestJavaFix_AFailingDeleteIsNotApplied(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	t.Setenv("KEYTOOL_FAIL_DELETE", "1")
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Equal(t, before, j.aliases())
	assert.Empty(t, j.priv.Commands)
}

func TestJavaFix_APatchedCopyThatStillTrustsTheChainIsNotInstalled(t *testing.T) {
	j := newJDK(t, jdkOpts{forcePatched: "trusted"})
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Equal(t, before, j.aliases())
	assert.Empty(t, j.priv.Commands, "no backup, no install")
	assert.Contains(t, j.out.String(), "STILL accepts the chain with the patched store")
}

func TestJavaFix_AnInconclusiveCopyTestWarnsAndGoesOn(t *testing.T) {
	// The script warns ("could not test the patched copy") and continues; the live
	// verification afterwards is what decides.
	j := newJDK(t, jdkOpts{forcePatched: "inconclusive"})
	require.Equal(t, fixrun.Changed, j.run(), j.out.String())
	assert.Contains(t, j.out.String(), "could not test the patched copy")
}

func TestJavaFix_AFailedInstallRestoresTheBackup(t *testing.T) {
	failInstall := func(c string) error {
		if strings.HasPrefix(c, "cp ") && !strings.HasPrefix(c, "cp -p ") {
			return fmt.Errorf("no space left on device")
		}
		return nil
	}
	j := newJDK(t, jdkOpts{noSudo: false, failOn: failInstall})
	// make the store need root so the install goes through the escalator we can fail
	j.priv.IsRootVal = false
	j.priv.HasSudoVal = true
	j.priv.NeedsMap = map[string]bool{j.cacerts: true}
	assert.Equal(t, fixrun.Failed, j.run())
	assert.True(t, j.restoreRecorded(), "the backup must be copied back: %q", j.priv.Commands)
}

func TestJavaFix_AFailedVerificationRestoresTheBackup(t *testing.T) {
	j := newJDK(t, jdkOpts{forceLive: "trusted"})
	j.priv.IsRootVal = false
	j.priv.HasSudoVal = true
	j.priv.NeedsMap = map[string]bool{j.cacerts: true}
	// root install is only recorded by the fake, so the live JDK still has the roots
	assert.Equal(t, fixrun.Failed, j.run(), "a JDK that still trusts the chain is not a success")
	assert.True(t, j.restoreRecorded(), "commands: %q", j.priv.Commands)
}

func TestJavaFix_NoSudoIsARefusalBeforeAnythingRuns(t *testing.T) {
	j := newJDK(t, jdkOpts{noSudo: true})
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Empty(t, j.priv.Commands)
	assert.Equal(t, before, j.aliases())
	assert.Contains(t, j.out.String(), "sudo is not available")
}

// The script has two separate checks on the patched copy, and they overlap whenever a delete
// removes nothing. Each of these makes only ONE of them fire, so removing either check is seen.
func TestJavaFix_RootsStillPresentButTheCountIsRight(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	t.Setenv("KEYTOOL_DELETE_WRONG", "1") // deletes an innocent entry: count drops by the planned amount
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Equal(t, before, j.aliases())
	assert.Empty(t, j.priv.Commands, "nothing may be backed up or installed")
	assert.Contains(t, j.out.String(), "the roots are still present after deletion")
}

func TestJavaFix_RootsGoneButTooManyEntriesWereRemoved(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	t.Setenv("KEYTOOL_DELETE_EXTRA", "1") // also deletes an innocent entry
	before := j.aliases()
	assert.Equal(t, fixrun.Failed, j.run())
	assert.Equal(t, before, j.aliases())
	assert.Empty(t, j.priv.Commands)
	assert.Contains(t, j.out.String(), "removed a different number of entries than planned")
}

// The common case: a JDK the user owns (SDKMAN, asdf, ~/.jdks), so no root is involved
// and the install is done by the fixer itself, not by a privileged cp.
func TestJavaFix_UserOwnedJDKIsPatchedForReal(t *testing.T) {
	j := newJDK(t, jdkOpts{}) // the fake escalator says the store is writable by us
	require.Equal(t, fixrun.Changed, j.run(), j.out.String())
	assert.ElementsMatch(t, []string{"digicert", "isrg", "lets"}, j.aliases(), "the user-owned store really changed")
	info, err := os.Stat(j.cacerts)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the mode is kept")
}

// A crash while writing a CA store must not leave a truncated one. The new store is built
// beside the original and renamed over it, so the original inode is never written to: a
// hard link made beforehand keeps the original content.
func TestJavaFix_UserOwnedInstallNeverWritesTheOriginalInPlace(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	link := j.cacerts + ".hardlink"
	require.NoError(t, os.Link(j.cacerts, link))
	original, err := os.ReadFile(j.cacerts)
	require.NoError(t, err)

	require.Equal(t, fixrun.Changed, j.run(), j.out.String())
	preserved, err := os.ReadFile(link)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(preserved), "the original inode must be untouched")
	now, err := os.ReadFile(j.cacerts)
	require.NoError(t, err)
	assert.NotEqual(t, string(original), string(now), "while the path holds the patched store")
}

// WriteFile's mode is masked by the process umask, so only an explicit chmod gives the new
// store exactly the original's mode. A group-writable store (0664) is what a umask of 022 would
// otherwise turn into 0644.
func TestInstallAtomic_KeepsTheExactOriginalMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o640, 0o600} {
		dir := t.TempDir()
		dst := filepath.Join(dir, "cacerts")
		src := filepath.Join(dir, "new")
		require.NoError(t, os.WriteFile(dst, []byte("old"), 0o644))
		require.NoError(t, os.Chmod(dst, mode))
		require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))

		require.NoError(t, installAtomic(src, dst))
		info, err := os.Stat(dst)
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm(), "mode %o must survive", mode)
		b, _ := os.ReadFile(dst)
		assert.Equal(t, "new", string(b))
		assert.NoFileExists(t, dst+".emudhra-new", "no temp file left behind")
	}
}

func TestInstallAtomic_LeavesTheOriginalIntactWhenItCannotInstall(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "cacerts")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o644))
	err := installAtomic(filepath.Join(dir, "does-not-exist"), dst)
	require.Error(t, err)
	b, _ := os.ReadFile(dst)
	assert.Equal(t, "old", string(b), "a failed install leaves the original alone")

	// a missing destination is refused rather than created
	assert.Error(t, installAtomic(dst, filepath.Join(dir, "nope")))
}

func TestInstallAtomic_AFailedRenameLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new")
	dst := filepath.Join(dir, "cacerts")
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))
	// dst is a non-empty directory: it exists (so Stat passes) and the temp file can be
	// written beside it, but renaming a file over a directory fails.
	require.NoError(t, os.MkdirAll(filepath.Join(dst, "inner"), 0o755))
	require.Error(t, installAtomic(src, dst))
	assert.NoFileExists(t, dst+".emudhra-new", "a failed install must not leave its temp file behind")
}

// ---- Undo --------------------------------------------------------------------------

func (j *jdk) writeBackup(stamp, content string) string {
	j.t.Helper()
	p := j.cacerts + ".pre-emudhra-" + stamp
	require.NoError(j.t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

func TestJavaUndo_RestoresTheNewestBackup(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.writeBackup("20260101000000", "old|Old\n")
	newest := j.writeBackup("20261023120000", "newest|Newest\n")
	j.writeBackup("20260601000000", "mid|Mid\n")
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.True(t, j.ran("cp -p "+newest+" "+j.cacerts), "the NEWEST backup is restored: %q", j.priv.Commands)
	assert.Equal(t, 1, countPrefix(j.priv.Commands, "cp -p "), "once: %q", j.priv.Commands)
}

func countPrefix(cmds []string, prefix string) (n int) {
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return
}

func TestJavaUndo_DryRunListsButChangesNothing(t *testing.T) {
	j := newJDK(t, jdkOpts{dryRun: true})
	j.writeBackup("20261023120000", "newest|Newest\n")
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.Empty(t, j.priv.Commands)
	assert.Contains(t, j.out.String(), "[dry-run] would restore it")
}

func TestJavaUndo_DecliningRestoresNothing(t *testing.T) {
	j := newJDK(t, jdkOpts{declined: true})
	j.writeBackup("20261023120000", "newest|Newest\n")
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.Empty(t, j.priv.Commands)
}

func TestJavaUndo_NothingToUndoIsQuiet(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.Empty(t, j.priv.Commands)
}

func TestJavaUndo_TheSameJDKReachedTwiceIsRestoredOnce(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.writeBackup("20261023120000", "newest|Newest\n")
	// JAVA_HOME and the replacement list both name it
	j.env.Environ["JAVA_HOME"] = j.home
	j.env.Environ["EMUDHRA_JAVA_HOMES"] = j.home + " " + j.home
	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{true, true}
	j.session.Prompt = pr
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.Equal(t, 1, countPrefix(j.priv.Commands, "cp -p "), "restored once, asked once: %q", j.priv.Commands)
	assert.Equal(t, 1, pr.ConfirmCalled)
}

func TestJavaUndo_RestoresEachDifferentJDK(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.writeBackup("20261023120000", "a|A\n")
	// a second JDK
	other := filepath.Join(filepath.Dir(j.home), "jdk2")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(other, "lib", "security"), 0o755))
	otherCacerts := filepath.Join(other, "lib", "security", "cacerts")
	require.NoError(t, os.WriteFile(otherCacerts, []byte("x|X\n"), 0o644))
	require.NoError(t, os.WriteFile(otherCacerts+".pre-emudhra-20261023120000", []byte("y|Y\n"), 0o644))
	j.env.Environ["EMUDHRA_JAVA_HOMES"] = j.home + " " + other
	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{true, true}
	j.session.Prompt = pr
	require.NoError(t, New().(*Kind).Undo(context.Background(), j.env, j.session))
	assert.Equal(t, 2, countPrefix(j.priv.Commands, "cp -p "), "%q", j.priv.Commands)
}

// ---- Audit, end to end through the stubs --------------------------------------------

func TestJavaAudit_FindsTheJDKAndDerivesTheStatus(t *testing.T) {
	cases := []struct {
		name    string
		force   string
		wantBad bool
	}{
		{"the JDK trusts the chain", "trusted", true},
		{"the JDK rejects the chain", "rejected", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := newJDK(t, jdkOpts{forceLive: c.force})
			findings, err := New().Audit(context.Background(), j.env)
			require.NoError(t, err)
			require.Len(t, findings, 1, j.out.String())
			assert.Equal(t, c.wantBad, findings[0].Status().IsBad(), findings[0].Status())
			assert.Equal(t, c.wantBad, findings[0].HasFix, "a fix is offered exactly when the JDK trusts the chain")
			assert.Empty(t, findings[0].Evidence, "a conclusive probe needs no reason, and raw probe output is not one")
		})
	}
}

func TestJavaAudit_OfflineSkipsTheProbe(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.env.Offline = true
	findings, err := New().Audit(context.Background(), j.env)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, kinds.ProbeSkipped, findings[0].ProbeResult)
	assert.Empty(t, j.plan(), "no probe result, so no store fix is planned")
}

func TestJavaAudit_NoJDKMeansNoFindings(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.env.Environ["EMUDHRA_JAVA_HOMES"] = filepath.Join(t.TempDir(), "nowhere")
	findings, err := New().Audit(context.Background(), j.env)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestJavaAudit_AJDKReachedTwiceIsReportedOnce(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	j.env.Environ["EMUDHRA_JAVA_HOMES"] = j.home + " " + j.home
	findings, err := New().Audit(context.Background(), j.env)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestJavaAudit_AnInconclusiveProbeCarriesOneLineOfReason(t *testing.T) {
	j := newJDK(t, jdkOpts{forceLive: "inconclusive"})
	findings, err := New().Audit(context.Background(), j.env)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, kinds.ProbeInconclusive, findings[0].ProbeResult)
	assert.Equal(t, "test hosts unreachable or failed for a non-certificate reason", findings[0].Evidence)
	assert.NotContains(t, findings[0].Evidence, "\n", "one line, as the report prints it after 'inconclusive - '")
}

// SDKMAN keeps a "current" symlink to the default JDK. The script reports a JDK by the
// directory it resolves to (cd -P), so the same JDK reached as "current" and by its real
// name is one finding, shown under its real name.
func TestJavaAudit_ASymlinkedJDKIsReportedUnderItsRealPath(t *testing.T) {
	j := newJDK(t, jdkOpts{})
	link := filepath.Join(filepath.Dir(j.home), "current")
	require.NoError(t, os.Symlink(j.home, link))
	j.env.Environ["EMUDHRA_JAVA_HOMES"] = link + " " + j.home

	findings, err := New().Audit(context.Background(), j.env)
	require.NoError(t, err)
	require.Len(t, findings, 1, "one JDK, however many names it has")
	assert.Equal(t, j.home, findings[0].Path, "shown under the directory it resolves to, not as 'current'")
}
