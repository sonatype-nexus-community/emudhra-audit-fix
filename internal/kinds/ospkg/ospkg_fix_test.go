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

package ospkg

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

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
)

const sampleConf = `mozilla/AC_RAIZ_FNMT-RCM.crt
mozilla/Comodo_AAA_Services_root.crt
mozilla/Certum_Trusted_Network_CA.crt
mozilla/emSign_ECC_Root_CA_-_G3.crt
mozilla/emSign_Root_CA_-_G1.crt
`

// rig is a fix run against a real temp directory with the user saying YES, so a
// confirmation can never hide a missing guard in the code under test.
type rig struct {
	t       *testing.T
	dir     string
	conf    string
	bundle  string
	priv    *privilege.FakeEscalator
	out     *bytes.Buffer
	session *fixrun.Session
	paths   Paths
	probes  int
}

type rigOpts struct {
	dryRun    bool
	noSudo    bool
	declined  bool
	conf      string // contents; "" means the file does not exist
	failOn    func(string) error
	verdict   probe.Verdict
	noUpdater bool // no update-ca-certificates on PATH
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{t: t, dir: dir, conf: filepath.Join(dir, "ca-certificates.conf"), bundle: filepath.Join(dir, "ca-certificates.crt"), out: &bytes.Buffer{}}
	if o.conf != "" {
		require.NoError(t, os.WriteFile(r.conf, []byte(o.conf), 0o644))
	}
	require.NoError(t, os.WriteFile(r.bundle, []byte("bundle"), 0o644))

	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	if !o.noUpdater {
		for _, c := range []string{"update-ca-certificates", "update-ca-trust", "trust"} {
			require.NoError(t, os.WriteFile(filepath.Join(bin, c), []byte("#!/bin/sh\n"), 0o755))
		}
	}

	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{!o.declined}
	r.priv = privilege.NewFakeEscalator()
	r.priv.IsRootVal = !o.noSudo
	r.priv.HasSudoVal = !o.noSudo
	if o.noSudo {
		r.priv.NeedsMap = map[string]bool{r.conf: true}
	}
	r.priv.FailOn = o.failOn

	verdict := o.verdict
	if verdict == "" {
		verdict = probe.VerdictRejected
	}
	r.paths = Paths{
		Conf: r.conf, PathEnv: bin,
		DebianBundles: []string{r.bundle}, P11Bundles: []string{r.bundle},
		ProbeFile: func(context.Context, string) (probe.Verdict, error) { r.probes++; return verdict, nil },
	}
	r.session = &fixrun.Session{DryRun: o.dryRun, TempDir: t.TempDir(), Stamp: "20261023120000", Prompt: pr, Priv: r.priv, Out: r.out}
	return r
}

func (r *rig) confBytes() string {
	r.t.Helper()
	b, err := os.ReadFile(r.conf)
	require.NoError(r.t, err)
	return string(b)
}

func (r *rig) ran(prefix string) bool {
	for _, c := range r.priv.Commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// restoreRecorded: the backup copied back over the original, "cp -p CONF.pre-emudhra-STAMP CONF".
func (r *rig) restoreRecorded() bool {
	return r.ran("cp -p "+r.conf+".pre-emudhra-") && strings.HasSuffix(r.lastRestore(), " "+r.conf)
}

func (r *rig) lastRestore() string {
	last := ""
	for _, c := range r.priv.Commands {
		if strings.HasPrefix(c, "cp -p "+r.conf+".pre-emudhra-") {
			last = c
		}
	}
	return last
}

func (r *rig) debian() *DebianLikeFix { return &DebianLikeFix{Paths: r.paths} }

// ---- the edit itself --------------------------------------------------------------

func TestDisableRoots(t *testing.T) {
	out, disabled := disableRoots(sampleConf)
	assert.Equal(t, "mozilla/AC_RAIZ_FNMT-RCM.crt\n!mozilla/Comodo_AAA_Services_root.crt\nmozilla/Certum_Trusted_Network_CA.crt\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\nmozilla/emSign_Root_CA_-_G1.crt\n", out,
		"exactly the two entries gain a ! and nothing else changes (emSign_Root_CA_-_G1 is a different root)")
	assert.Equal(t, []string{"mozilla/Comodo_AAA_Services_root.crt", "mozilla/emSign_ECC_Root_CA_-_G3.crt"}, disabled)

	again, d2 := disableRoots(out)
	assert.Equal(t, out, again, "already disabled entries are left alone")
	assert.Empty(t, d2)

	indented := "  mozilla/Comodo_AAA_Services_root.crt\n#mozilla/emSign_ECC_Root_CA_-_G3.crt\n"
	same, d3 := disableRoots(indented)
	assert.Equal(t, indented, same, "the script's sed is anchored with ^: indented and commented lines are not touched")
	assert.Empty(t, d3)
}

// ---- DebianLikeFix ------------------------------------------------------------------

func TestDebianFix_SuccessInstallsTheEditedFileAndRebuilds(t *testing.T) {
	r := newRig(t, rigOpts{conf: sampleConf})
	out := r.debian().Run(context.Background(), r.session)
	require.Equal(t, fixrun.Changed, out, r.out.String())

	// The escalator records "cp WORK CONF" without running it, so check the file that
	// is installed: it is the edited copy built in the session's temp directory.
	work := filepath.Join(r.session.TempDir, "ca-certificates.conf")
	assert.True(t, r.ran("cp "+work+" "+r.conf), "the edited copy is what gets installed: %q", r.priv.Commands)
	edited, err := os.ReadFile(work)
	require.NoError(t, err)
	assert.Contains(t, string(edited), "!mozilla/Comodo_AAA_Services_root.crt")
	assert.Contains(t, string(edited), "!mozilla/emSign_ECC_Root_CA_-_G3.crt")
	assert.Contains(t, string(edited), "\nmozilla/emSign_Root_CA_-_G1.crt", "an unrelated root must not be disabled")
	assert.Equal(t, sampleConf, r.confBytes(), "the live conf is only changed by the (recorded) privileged cp")

	assert.True(t, r.ran("cp -p "+r.conf+" "+r.conf+".pre-emudhra-"), "backed up first: %q", r.priv.Commands)
	assert.True(t, r.ran(filepath.Join(r.dir, "bin", "update-ca-certificates")), "bundle rebuilt: %q", r.priv.Commands)
	assert.GreaterOrEqual(t, r.probes, 1, "and verified with the probe")
}

func TestDebianFix_NeverRunsAPackageManager(t *testing.T) {
	for _, workaround := range []bool{false, true} {
		r := newRig(t, rigOpts{conf: sampleConf})
		f := r.debian()
		f.WorkaroundOnly = workaround
		f.Run(context.Background(), r.session)
		for _, c := range r.priv.Commands {
			assert.NotContains(t, c, "apt-get", "the script only PRINTS the vendor-package hint")
			assert.NotContains(t, c, "apk ")
		}
		if workaround {
			assert.NotContains(t, r.out.String(), "Preferred: the vendor's fixed package", "--workaround-only suppresses the hint")
		} else {
			assert.Contains(t, r.out.String(), "Preferred: the vendor's fixed package")
		}
	}
}

func TestDebianFix_DryRunChangesNothing(t *testing.T) {
	r := newRig(t, rigOpts{conf: sampleConf, dryRun: true})
	out := r.debian().Run(context.Background(), r.session)
	assert.Equal(t, fixrun.Skipped, out)
	assert.Equal(t, sampleConf, r.confBytes())
	assert.Empty(t, r.priv.Commands, "a dry run must not run a privileged command")
	assert.Contains(t, r.out.String(), "[dry-run]")
}

func TestDebianFix_DeclinedChangesNothing(t *testing.T) {
	r := newRig(t, rigOpts{conf: sampleConf, declined: true})
	assert.Equal(t, fixrun.Skipped, r.debian().Run(context.Background(), r.session))
	assert.Equal(t, sampleConf, r.confBytes())
	assert.Empty(t, r.priv.Commands)
}

func TestDebianFix_AlreadyCleanAndMissingAndNoUpdater(t *testing.T) {
	clean, _ := disableRoots(sampleConf)
	r := newRig(t, rigOpts{conf: clean})
	assert.Equal(t, fixrun.Skipped, r.debian().Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)
	assert.Contains(t, r.out.String(), "already clean")

	r = newRig(t, rigOpts{})
	assert.Equal(t, fixrun.Skipped, r.debian().Run(context.Background(), r.session))
	assert.Contains(t, r.out.String(), "not found")

	r = newRig(t, rigOpts{conf: sampleConf, noUpdater: true})
	assert.Equal(t, fixrun.Skipped, r.debian().Run(context.Background(), r.session))
	assert.Equal(t, sampleConf, r.confBytes())
	assert.Contains(t, r.out.String(), "update-ca-certificates not found")
}

func TestDebianFix_AFailedRebuildRestoresTheConf(t *testing.T) {
	failRebuild := func(c string) error {
		if strings.Contains(c, "update-ca-certificates") && !strings.HasPrefix(c, "cp ") {
			return fmt.Errorf("exit status 1")
		}
		return nil
	}
	r := newRig(t, rigOpts{conf: sampleConf, failOn: failRebuild})
	assert.Equal(t, fixrun.Failed, r.debian().Run(context.Background(), r.session))
	assert.True(t, r.restoreRecorded(), "the conf must be copied back: %q", r.priv.Commands)
}

func TestDebianFix_AFailedInstallRestoresTheConf(t *testing.T) {
	failInstall := func(c string) error {
		if strings.HasPrefix(c, "cp ") && !strings.HasPrefix(c, "cp -p ") {
			return fmt.Errorf("no space left on device")
		}
		return nil
	}
	r := newRig(t, rigOpts{conf: sampleConf, failOn: failInstall})
	assert.Equal(t, fixrun.Failed, r.debian().Run(context.Background(), r.session))
	assert.True(t, r.restoreRecorded(), "commands: %q", r.priv.Commands)
}

func TestDebianFix_FailedVerificationRestoresAndRebuildsFromTheBackup(t *testing.T) {
	r := newRig(t, rigOpts{conf: sampleConf, verdict: probe.VerdictTrusted})
	assert.Equal(t, fixrun.Failed, r.debian().Run(context.Background(), r.session), "a bundle that still trusts the chain is not a success")
	assert.True(t, r.restoreRecorded(), "commands: %q", r.priv.Commands)
	rebuilds := 0
	for _, c := range r.priv.Commands {
		if strings.HasSuffix(c, "update-ca-certificates") {
			rebuilds++
		}
	}
	assert.Equal(t, 2, rebuilds, "rebuilt once after the edit, and again after the restore: %q", r.priv.Commands)
}

func TestDebianFix_NoSudoIsARefusalBeforeAnythingRuns(t *testing.T) {
	r := newRig(t, rigOpts{conf: sampleConf, noSudo: true})
	assert.Equal(t, fixrun.Failed, r.debian().Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)
	assert.Contains(t, r.out.String(), "sudo is not available")
}

// ---- P11BlocklistFix ----------------------------------------------------------------

func (r *rig) p11() *P11BlocklistFix {
	src := filepath.Join(r.dir, "trust")
	require.NoError(r.t, os.MkdirAll(src, 0o755))
	r.paths.BlocklistRoots = []blocklistRoot{{Source: src, Dirs: []string{filepath.Join(src, "blocklist"), filepath.Join(src, "blacklist")}}}
	// The fake escalator records "mkdir -p DIR" without running it. The real command
	// would have created the directory, and removing the entries again refuses unless
	// the directory exists (the script's own guard), so create it as mkdir would.
	require.NoError(r.t, os.MkdirAll(filepath.Join(src, "blocklist"), 0o755))
	return &P11BlocklistFix{Paths: r.paths}
}

func TestP11Fix_SuccessWritesBothRootsAndTheMarkerAndRebuilds(t *testing.T) {
	r := newRig(t, rigOpts{})
	f := r.p11()
	dir := filepath.Join(r.dir, "trust", "blocklist")
	out := f.Run(context.Background(), r.session)
	require.Equal(t, fixrun.Changed, out, r.out.String())

	assert.True(t, r.ran("mkdir -p "+dir), "commands: %q", r.priv.Commands)
	for _, file := range []string{emSignFile, comodoFile} {
		assert.True(t, r.ran(fmt.Sprintf("%s extract --overwrite --format=pem-bundle", filepath.Join(r.dir, "bin", "trust"))) &&
			containsCmd(r.priv.Commands, filepath.Join(dir, file)), "extracts %s: %q", file, r.priv.Commands)
	}
	assert.True(t, containsCmd(r.priv.Commands, markerFile), "the marker that lets --undo recognise our files must be written: %q", r.priv.Commands)
	assert.True(t, containsCmd(r.priv.Commands, "update-ca-trust"), "bundle rebuilt: %q", r.priv.Commands)
	assert.GreaterOrEqual(t, r.probes, 1)
}

func containsCmd(cmds []string, sub string) bool {
	for _, c := range cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestP11Fix_PrefersBlocklistFallsBackToBlacklist(t *testing.T) {
	r := newRig(t, rigOpts{})
	src := filepath.Join(r.dir, "trust")
	require.NoError(t, os.MkdirAll(filepath.Join(src, "blacklist"), 0o755)) // only the OLD name exists
	paths := r.paths
	paths.BlocklistRoots = []blocklistRoot{{Source: src, Dirs: []string{filepath.Join(src, "blocklist"), filepath.Join(src, "blacklist")}}}
	assert.Equal(t, filepath.Join(src, "blacklist"), paths.blocklistDir(), "an existing old-style directory is used")

	require.NoError(t, os.MkdirAll(filepath.Join(src, "blocklist"), 0o755))
	assert.Equal(t, filepath.Join(src, "blocklist"), paths.blocklistDir(), "blocklist is preferred when both exist")
}

func TestP11Fix_DryRunDeclinedAndAlreadyDoneChangeNothing(t *testing.T) {
	r := newRig(t, rigOpts{dryRun: true})
	assert.Equal(t, fixrun.Skipped, r.p11().Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)
	// A dry run exists to SHOW the plan. Session.Confirm also refuses in a dry run, so
	// "nothing ran" alone cannot tell the Fix's own dry-run branch from that second
	// guard; the printed commands can.
	assert.Contains(t, r.out.String(), "trust extract --format=pem-bundle", "a dry run must print the commands it would run")
	assert.Contains(t, r.out.String(), emSignFile)
	assert.Contains(t, r.out.String(), comodoFile)
	assert.Contains(t, r.out.String(), "update-ca-trust")

	r = newRig(t, rigOpts{declined: true})
	assert.Equal(t, fixrun.Skipped, r.p11().Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)

	r = newRig(t, rigOpts{})
	f := r.p11()
	dir := filepath.Join(r.dir, "trust", "blocklist")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, emSignFile), []byte("x"), 0o644))
	assert.Equal(t, fixrun.Skipped, f.Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)
	assert.Contains(t, r.out.String(), "already clean")
}

func TestP11Fix_NoTrustCommandOrNoDirectoryIsSkipped(t *testing.T) {
	r := newRig(t, rigOpts{noUpdater: true})
	assert.Equal(t, fixrun.Skipped, r.p11().Run(context.Background(), r.session))
	assert.Contains(t, r.out.String(), "'trust' command not found")

	r = newRig(t, rigOpts{})
	r.paths.BlocklistRoots = []blocklistRoot{{Source: filepath.Join(r.dir, "nope"), Dirs: []string{filepath.Join(r.dir, "nope", "blocklist")}}}
	assert.Equal(t, fixrun.Skipped, (&P11BlocklistFix{Paths: r.paths}).Run(context.Background(), r.session))
	assert.Contains(t, r.out.String(), "no known trust-source directory")
}

func TestP11Fix_AFailedExtractRemovesWhatWasAdded(t *testing.T) {
	failComodo := func(c string) error {
		if strings.Contains(c, " extract ") && strings.Contains(c, comodoFile) {
			return fmt.Errorf("exit status 1")
		}
		return nil
	}
	r := newRig(t, rigOpts{failOn: failComodo})
	assert.Equal(t, fixrun.Failed, r.p11().Run(context.Background(), r.session))
	assert.True(t, containsCmd(r.priv.Commands, "rm -f"), "the half-added files must be removed: %q", r.priv.Commands)
}

func TestP11Fix_AFailedRebuildRemovesTheEntries(t *testing.T) {
	// Fail the FIRST update-ca-trust (the rebuild after the extract); the second one,
	// the rebuild after the rollback, must be allowed to succeed.
	rebuilds := 0
	failFirstRebuild := func(c string) error {
		if strings.HasSuffix(c, "update-ca-trust") {
			rebuilds++
			if rebuilds == 1 {
				return fmt.Errorf("exit status 1")
			}
		}
		return nil
	}
	r := newRig(t, rigOpts{failOn: failFirstRebuild})
	assert.Equal(t, fixrun.Failed, r.p11().Run(context.Background(), r.session))
	assert.True(t, containsCmd(r.priv.Commands, "rm -f"), "the entries must be removed: %q", r.priv.Commands)
	assert.Equal(t, 2, rebuilds, "and the bundle rebuilt again without them: %q", r.priv.Commands)
}

func TestP11Fix_FailedVerificationRemovesTheEntriesAndRebuilds(t *testing.T) {
	r := newRig(t, rigOpts{verdict: probe.VerdictTrusted})
	assert.Equal(t, fixrun.Failed, r.p11().Run(context.Background(), r.session))
	rm := -1
	for i, c := range r.priv.Commands {
		if strings.HasPrefix(c, "rm -f") {
			rm = i
		}
	}
	require.GreaterOrEqual(t, rm, 0, "the blocklist entries must be removed: %q", r.priv.Commands)
	assert.True(t, strings.HasSuffix(r.priv.Commands[len(r.priv.Commands)-1], "update-ca-trust"), "and the bundle rebuilt after: %q", r.priv.Commands)
	assert.Contains(t, r.priv.Commands[rm], markerFile, "the marker is removed with the files")
}

func TestP11Fix_NoSudoIsARefusal(t *testing.T) {
	r := newRig(t, rigOpts{noSudo: true})
	f := r.p11()
	dir := filepath.Join(r.dir, "trust", "blocklist")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	r.priv.NeedsMap = map[string]bool{dir: true}
	assert.Equal(t, fixrun.Failed, f.Run(context.Background(), r.session))
	assert.Empty(t, r.priv.Commands)
}

func TestRemoveBlocklistFilesRefusesAnUnsafeDirectory(t *testing.T) {
	for _, dir := range []string{"", "/", "relative/dir", "/does/not/exist"} {
		r := newRig(t, rigOpts{})
		err := removeBlocklistFiles(context.Background(), r.session, dir)
		assert.Error(t, err, "dir %q", dir)
		assert.Empty(t, r.priv.Commands, "an empty or relative directory must never become rm -f /emSign_...")
	}
}

// ---- Undo ---------------------------------------------------------------------------

func TestUndo_RestoresTheNewestConfBackup(t *testing.T) {
	r := newRig(t, rigOpts{conf: "current\n"})
	require.NoError(t, os.WriteFile(r.conf+".pre-emudhra-20260101000000", []byte("old"), 0o644))
	require.NoError(t, os.WriteFile(r.conf+".pre-emudhra-20261023120000", []byte("newest"), 0o644))
	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	assert.True(t, r.ran("cp -p "+r.conf+".pre-emudhra-20261023120000 "+r.conf), "the NEWEST backup is restored: %q", r.priv.Commands)
	assert.True(t, containsCmd(r.priv.Commands, "update-ca-certificates"), "and the bundle rebuilt: %q", r.priv.Commands)
}

func TestUndo_RemovesOnlyDirectoriesThatHoldOurMarker(t *testing.T) {
	r := newRig(t, rigOpts{})
	src := filepath.Join(r.dir, "trust")
	ours, theirs := filepath.Join(src, "blocklist"), filepath.Join(src, "blacklist")
	require.NoError(t, os.MkdirAll(ours, 0o755))
	require.NoError(t, os.MkdirAll(theirs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ours, markerFile), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(theirs, emSignFile), []byte("an admin's own entry"), 0o644)) // no marker
	r.paths.BlocklistRoots = []blocklistRoot{{Source: src, Dirs: []string{ours, theirs}}}
	r.session.Prompt = func() prompt.Prompter {
		p := prompt.NewFakePrompter()
		p.ConfirmResponses = []bool{true, true}
		return p
	}()

	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	removed := ""
	for _, c := range r.priv.Commands {
		if strings.HasPrefix(c, "rm -f") {
			removed += c
		}
	}
	assert.Contains(t, removed, ours, "our marked directory is cleaned")
	assert.NotContains(t, removed, theirs, "a directory WITHOUT our marker must never be touched")
	assert.True(t, strings.HasSuffix(r.priv.Commands[len(r.priv.Commands)-1], "update-ca-trust"),
		"the trust bundle must be rebuilt AFTER the entries are removed, or the system keeps distrusting the roots: %q", r.priv.Commands)
}

func TestUndo_DryRunListsButChangesNothing(t *testing.T) {
	r := newRig(t, rigOpts{conf: "current\n", dryRun: true})
	require.NoError(t, os.WriteFile(r.conf+".pre-emudhra-20261023120000", []byte("b"), 0o644))
	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	assert.Empty(t, r.priv.Commands)
	assert.Contains(t, r.out.String(), "[dry-run] would restore it")
}

func TestUndo_NothingToUndoIsQuiet(t *testing.T) {
	r := newRig(t, rigOpts{conf: "current\n"})
	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	assert.Empty(t, r.priv.Commands)
}

// Undo restores system files and deletes trust entries: it must ask, and a "no"
// must leave everything as it is.
func TestUndo_DeclinedChangesNothing(t *testing.T) {
	r := newRig(t, rigOpts{conf: "current\n", declined: true})
	require.NoError(t, os.WriteFile(r.conf+".pre-emudhra-20261023120000", []byte("b"), 0o644))
	src := filepath.Join(r.dir, "trust")
	ours := filepath.Join(src, "blocklist")
	require.NoError(t, os.MkdirAll(ours, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ours, markerFile), []byte("x"), 0o644))
	r.paths.BlocklistRoots = []blocklistRoot{{Source: src, Dirs: []string{ours}}}
	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{false, false} // refuse both the blocklist removal and the conf restore
	r.session.Prompt = pr

	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	assert.Empty(t, r.priv.Commands, "declining must run nothing: %q", r.priv.Commands)
	assert.Equal(t, 2, pr.ConfirmCalled, "both the removal and the restore must be asked about")
	assert.Equal(t, "current\n", r.confBytes())
	assert.FileExists(t, filepath.Join(ours, markerFile))
}

// When both are present the newest backup wins, so the order the names sort in matters.
func TestUndo_NewestBackupWinsOverAnOlderOne(t *testing.T) {
	r := newRig(t, rigOpts{conf: "current\n"})
	for _, st := range []string{"20260601000000", "20261023120000", "20260101000000"} {
		require.NoError(t, os.WriteFile(r.conf+".pre-emudhra-"+st, []byte(st), 0o644))
	}
	require.NoError(t, undoWith(context.Background(), r.session, r.paths))
	require.True(t, r.ran("cp -p "+r.conf+".pre-emudhra-"), "%q", r.priv.Commands)
	assert.True(t, r.ran("cp -p "+r.conf+".pre-emudhra-20261023120000 "+r.conf), "restored from the newest: %q", r.priv.Commands)
	assert.False(t, r.ran("cp -p "+r.conf+".pre-emudhra-20260101000000 "), "never the oldest")
}
