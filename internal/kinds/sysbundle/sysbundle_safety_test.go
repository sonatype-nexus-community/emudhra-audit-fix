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

package sysbundle

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

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/advisory"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/trust"
)

// harness runs BundleFix on a real temp bundle with the user saying yes, so the
// confirmation can never mask a missing guard in the code under test.
type harness struct {
	t          *testing.T
	path       string
	orig       []byte
	priv       *privilege.FakeEscalator
	out        *bytes.Buffer
	session    *fixrun.Session
	probeCalls []string // the files handed to the probe, in order
}

type harnessOpts struct {
	bundle     []byte
	dryRun     bool
	needsRoot  bool
	noSudo     bool
	failOn     func(string) error
	confirmYes bool
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(path, o.bundle, 0o600))

	pr := prompt.NewFakePrompter()
	pr.ConfirmResponses = []bool{o.confirmYes}
	priv := privilege.NewFakeEscalator()
	priv.IsRootVal = !o.needsRoot
	priv.HasSudoVal = !o.noSudo
	if o.needsRoot {
		priv.NeedsMap = map[string]bool{path: true}
	}
	priv.FailOn = o.failOn

	h := &harness{t: t, path: path, orig: o.bundle, priv: priv, out: &bytes.Buffer{}}
	h.session = &fixrun.Session{
		DryRun: o.dryRun, TempDir: t.TempDir(), Stamp: "20260123120000",
		Prompt: pr, Priv: priv, Out: h.out,
	}
	return h
}

func (h *harness) run(patched, installed probe.Verdict) fixrun.Outcome {
	h.t.Helper()
	calls := 0
	fix := &BundleFix{
		Path:  h.path,
		Probe: probe.NewFakeEngine(),
		ProbeCAFile: func(_ context.Context, caFile string) ([]probe.ProbeResult, error) {
			h.probeCalls = append(h.probeCalls, caFile)
			calls++
			v := patched
			if calls > 1 {
				v = installed
			}
			return []probe.ProbeResult{
				{URL: probe.CONTROL_URL, Verdict: probe.VerdictTrusted},
				{URL: probe.BAD_URLS[0], Verdict: v},
				{URL: probe.BAD_URLS[1], Verdict: v},
			}, nil
		},
	}
	return fix.Run(context.Background(), h.session)
}

func (h *harness) contents() []byte {
	h.t.Helper()
	b, err := os.ReadFile(h.path)
	require.NoError(h.t, err)
	return b
}

// restoreRecorded reports whether the backup was copied back over the original:
// "cp -p <path>.pre-emudhra-STAMP <path>". The backup itself is the reverse,
// "cp -p <path> <path>.pre-emudhra-STAMP", and must not count.
func (h *harness) restoreRecorded() bool {
	prefix := "cp -p " + h.path + ".pre-emudhra-"
	for _, c := range h.priv.Commands {
		if strings.HasPrefix(c, prefix) && strings.HasSuffix(c, " "+h.path) {
			return true
		}
	}
	return false
}

func hasBadRoots(t *testing.T, data []byte) bool {
	t.Helper()
	b, err := trust.ParseBundle(data)
	require.NoError(t, err)
	return b.ContainsRoot()
}

// Dry run must not change the machine even when the user would have said yes.
// (Before this test existed, a missing dry-run guard was hidden by the
// confirmation: the fake prompt answered no.)
func TestSafety_DryRunNeverInstalls(t *testing.T) {
	for _, needsRoot := range []bool{false, true} {
		t.Run(fmt.Sprintf("needsRoot=%v", needsRoot), func(t *testing.T) {
			h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), dryRun: true, needsRoot: needsRoot, confirmYes: true})
			out := h.run(probe.VerdictRejected, probe.VerdictRejected)
			assert.Equal(t, fixrun.Skipped, out)
			assert.Equal(t, h.orig, h.contents(), "dry run must not touch the file")
			assert.Empty(t, h.priv.Commands, "dry run must not run a privileged command")
			assert.NoFileExists(t, h.path+".tmp", "dry run must not leave a temp file")
			assert.Contains(t, h.out.String(), "[dry-run]")
		})
	}
}

// The user-owned install branch is the atomic write-then-rename: the mode is
// kept, the bad roots are gone, no temp file is left behind.
func TestSafety_UserOwnedInstallIsAtomicAndKeepsMode(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), confirmYes: true})
	// not root and the file is writable by us: Backup still goes through AsRoot (the
	// fake records it), the install itself is the rename.
	out := h.run(probe.VerdictRejected, probe.VerdictRejected)
	require.Equal(t, fixrun.Changed, out, h.out.String())

	info, err := os.Stat(h.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the original mode must survive")
	assert.False(t, hasBadRoots(t, h.contents()), "the installed bundle must not contain the roots")
	assert.NoFileExists(t, h.path+".tmp", "no temp file may be left behind")
}

// An install that fails AFTER the backup succeeded must put the original back.
func TestSafety_InstallFailureRestoresTheBackup(t *testing.T) {
	failInstall := func(c string) error {
		// the install is "cp <patched> <path>"; the backup is "cp -p <path> <backup>"
		if strings.HasPrefix(c, "cp ") && !strings.HasPrefix(c, "cp -p ") {
			return fmt.Errorf("no space left on device")
		}
		return nil
	}
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), needsRoot: true, confirmYes: true, failOn: failInstall})
	out := h.run(probe.VerdictRejected, probe.VerdictRejected)

	assert.Equal(t, fixrun.Failed, out)
	assert.True(t, h.restoreRecorded(), "the backup must be copied back; commands: %q", h.priv.Commands)
	assert.Equal(t, h.orig, h.contents(), "the original bundle must be untouched")
}

// Verification after the install must be what decides Changed.
func TestSafety_FailedVerificationRestoresAndIsNotChanged(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), needsRoot: true, confirmYes: true})
	out := h.run(probe.VerdictRejected, probe.VerdictTrusted) // installed file still trusts the chain
	assert.Equal(t, fixrun.Failed, out)
	assert.True(t, h.restoreRecorded(), "commands: %q", h.priv.Commands)
}

// Nothing is installed before the patched COPY has been probed.
func TestSafety_PatchedCopyIsProbedBeforeAnythingIsInstalled(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), needsRoot: true, confirmYes: true})
	h.run(probe.VerdictRejected, probe.VerdictRejected)
	require.GreaterOrEqual(t, len(h.probeCalls), 2)
	assert.NotEqual(t, h.path, h.probeCalls[0], "the first probe must be of the patched COPY, not the live file")
	assert.Equal(t, h.path, h.probeCalls[1], "the second probe is of the installed file")
}

// A patched copy that still trusts the chain, or cannot be judged, must never be installed.
func TestSafety_UnverifiedPatchedCopyIsNotInstalled(t *testing.T) {
	for name, v := range map[string]probe.Verdict{"still trusts": probe.VerdictTrusted, "inconclusive": probe.VerdictInconclusive} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), needsRoot: true, confirmYes: true})
			out := h.run(v, probe.VerdictRejected)
			assert.Equal(t, fixrun.Failed, out)
			assert.Empty(t, h.priv.Commands, "no backup and no install may run: %q", h.priv.Commands)
			assert.Equal(t, h.orig, h.contents())
		})
	}
}

// An already-clean bundle needs no change at all.
func TestSafety_CleanBundleIsLeftAlone(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, false), needsRoot: true, confirmYes: true})
	out := h.run(probe.VerdictRejected, probe.VerdictRejected)
	assert.Equal(t, fixrun.Skipped, out)
	assert.Empty(t, h.priv.Commands)
	assert.Equal(t, h.orig, h.contents())
}

// Needing root without a way to get it is a refusal, before anything runs.
func TestSafety_NoSudoIsARefusal(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), needsRoot: true, noSudo: true, confirmYes: true})
	out := h.run(probe.VerdictRejected, probe.VerdictRejected)
	assert.Equal(t, fixrun.Failed, out)
	assert.Empty(t, h.priv.Commands, "no command may run without a way to get root")
	assert.Equal(t, h.orig, h.contents())
	assert.Contains(t, h.out.String(), "sudo is not available")
}

// A bundle holding the same root more than once (two sources concatenated)
// would lose three certificates, not two. The fix removes exactly the two
// roots, so it must refuse rather than guess.
func TestSafety_MoreThanTwoRemovalsIsRefused(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(generateTestCertificate(t, "Good Root CA 1"))
	buf.Write(generateTestCertificate(t, advisory.RootAAACertificateServices))
	buf.Write(generateTestCertificate(t, advisory.RootAAACertificateServices)) // the same root again
	buf.Write(generateTestCertificate(t, advisory.RootEmSignECCRootCAG3))

	h := newHarness(t, harnessOpts{bundle: buf.Bytes(), needsRoot: true, confirmYes: true})
	out := h.run(probe.VerdictRejected, probe.VerdictRejected)

	assert.Equal(t, fixrun.Failed, out)
	assert.Empty(t, h.priv.Commands, "nothing may be backed up or installed: %q", h.priv.Commands)
	assert.Equal(t, h.orig, h.contents())
	assert.Contains(t, h.out.String(), "refusing")
}

// The user-owned install must never write into the original file: it builds the
// new bundle beside it and renames it over, so a crash mid-write cannot leave a
// truncated CA bundle. A hard link made beforehand keeps pointing at the
// original inode, so its content proves the original was not written to.
func TestSafety_UserOwnedInstallNeverWritesTheOriginalInPlace(t *testing.T) {
	h := newHarness(t, harnessOpts{bundle: generateTestBundle(t, true), confirmYes: true})
	link := h.path + ".hardlink"
	require.NoError(t, os.Link(h.path, link))

	out := h.run(probe.VerdictRejected, probe.VerdictRejected)
	require.Equal(t, fixrun.Changed, out, h.out.String())

	preserved, err := os.ReadFile(link)
	require.NoError(t, err)
	assert.Equal(t, h.orig, preserved, "the original inode must be untouched: the new bundle is renamed over it")
	assert.NotEqual(t, h.orig, h.contents(), "while the path now holds the patched bundle")
}
