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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/discover"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/fixrun"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
)

// Where the system trust store fixes look and act. The zero value is the
// script's real locations; tests point every field at a temp directory and give
// the probe a fake, so nothing outside the test is read or written.
type Paths struct {
	// Conf is /etc/ca-certificates.conf (Debian, Ubuntu, Alpine).
	Conf string
	// PathEnv is the PATH used to find update-ca-certificates, update-ca-trust and trust.
	PathEnv string
	// BlocklistRoots lists, in the script's order, the p11-kit trust-source roots; the
	// blocklist directory is chosen from the first root that exists.
	BlocklistRoots []blocklistRoot
	// BundleCandidates are the bundles probed after a change (first that exists wins).
	DebianBundles []string
	P11Bundles    []string
	// ProbeFile judges a CA bundle file against the compromised chain.
	ProbeFile func(ctx context.Context, caFile string) (probe.Verdict, error)
}

type blocklistRoot struct {
	Source string   // directory whose existence selects this layout
	Dirs   []string // blocklist directory names to prefer, in order
}

func (p Paths) conf() string {
	if p.Conf != "" {
		return p.Conf
	}
	return "/etc/ca-certificates.conf"
}

func (p Paths) roots() []blocklistRoot {
	if p.BlocklistRoots != nil {
		return p.BlocklistRoots
	}
	return []blocklistRoot{
		{"/etc/pki/ca-trust/source", []string{"/etc/pki/ca-trust/source/blocklist", "/etc/pki/ca-trust/source/blacklist"}},
		{"/etc/pki/trust", []string{"/etc/pki/trust/blocklist", "/etc/pki/trust/blacklist"}},
		{"/etc/ca-certificates/trust-source", []string{"/etc/ca-certificates/trust-source/blocklist"}},
	}
}

func (p Paths) debianBundles() []string {
	if p.DebianBundles != nil {
		return p.DebianBundles
	}
	return []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"}
}

func (p Paths) p11Bundles() []string {
	if p.P11Bundles != nil {
		return p.P11Bundles
	}
	return []string{"/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/certs/ca-certificates.crt"}
}

// probeBundle ports probe_cafile for a system bundle: the verdict of the first
// bundle in the list that exists, or "" when none does.
func (p Paths) probeBundle(ctx context.Context, bundles []string) probe.Verdict {
	for _, b := range bundles {
		if _, err := os.Stat(b); err != nil {
			continue
		}
		judge := p.ProbeFile
		if judge == nil {
			judge = defaultProbeFile
		}
		v, err := judge(ctx, b)
		if err != nil {
			return probe.VerdictInconclusive
		}
		return v
	}
	return ""
}

func defaultProbeFile(ctx context.Context, caFile string) (probe.Verdict, error) {
	results, err := probe.ProbeCAFile(ctx, caFile)
	if err != nil {
		return "", err
	}
	return probe.NewRealEngine().Judge(results), nil
}

// which finds a command on the PATH, as `command -v`.
func (p Paths) which(name string) string {
	return discover.Lookup(name, p.PathEnv)
}

// The three files fix_p11_blocklist creates, and the marker that lets --undo
// recognise them as ours.
const (
	emSignFile  = "emSign_ECC_Root_CA_-_G3.pem"
	comodoFile  = "Comodo_AAA_Services_root.pem"
	markerFile  = ".emudhra-audit-created"
	emSignQuery = "--filter=pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert"
	comodoQuery = "--filter=pkcs11:object=Comodo%20AAA%20Services%20root;type=cert"
)

var disableLine = regexp.MustCompile(`^mozilla/(emSign_ECC_Root_CA_-_G3|Comodo_AAA_Services_root)\.crt`)

// disableRoots ports the script's
//
//	sed -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|'
//
// A line is touched only if it BEGINS with the entry (the sed is anchored with ^),
// so an indented or commented line is left exactly as it is.
func disableRoots(conf string) (out string, disabled []string) {
	lines := strings.Split(conf, "\n")
	for i, l := range lines {
		if disableLine.MatchString(l) {
			lines[i] = "!" + l
			disabled = append(disabled, l)
		}
	}
	return strings.Join(lines, "\n"), disabled
}

// DebianLikeFix ports fix_debian_like: disable the two roots in
// /etc/ca-certificates.conf and rebuild the bundle with update-ca-certificates.
// The vendor-package hint is only printed (by fix_system); nothing here runs a
// package manager.
type DebianLikeFix struct {
	WorkaroundOnly bool
	DistroID       string
	DistroVersion  string
	Paths          Paths
}

func (f *DebianLikeFix) Kind() string   { return "ospkg" }
func (f *DebianLikeFix) Target() string { return f.Paths.conf() }

func (f *DebianLikeFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	conf := f.Paths.conf()

	// fix_system prints the vendor hint; --workaround-only only suppresses it.
	if !f.WorkaroundOnly {
		s.Say("Preferred: the vendor's fixed package (apt-get install --only-upgrade ca-certificates / apk upgrade ca-certificates).")
	}
	s.Say("%s  (Debian/Ubuntu/Alpine CA configuration)", s.Bold(conf))

	data, err := os.ReadFile(conf)
	if err != nil {
		s.Warn("not found")
		return fixrun.Skipped
	}
	update := f.Paths.which("update-ca-certificates")
	if update == "" {
		s.Warn("update-ca-certificates not found - cannot rebuild the bundle")
		return fixrun.Skipped
	}

	edited, disabled := disableRoots(string(data))
	if edited == string(data) {
		s.OK("already clean - both roots are already disabled (or not listed)")
		return fixrun.Skipped
	}
	s.Say("would disable: %s ", strings.Join(disabled, " "))

	work := filepath.Join(s.TempDir, "ca-certificates.conf")
	if err := os.WriteFile(work, []byte(edited), 0o644); err != nil {
		s.Bad("cannot write a temporary copy: %v", err)
		return fixrun.Failed
	}
	bak := s.BackupPath(conf)

	if s.DryRun {
		s.Say("[dry-run] would back up to %s, install the edited file and run update-ca-certificates", bak)
		s.Cmd("cp -p %s %s", conf, bak)
		s.Cmd("cp %s %s && update-ca-certificates", work, conf)
		return fixrun.Skipped
	}
	if !s.Confirm(fmt.Sprintf("Disable the two roots in %s and rebuild the bundle?", conf)) {
		s.Say("skipped")
		return fixrun.Skipped
	}
	if _, err := s.NeedRoot(conf); err != nil {
		return fixrun.Failed
	}
	if _, err := s.Backup(ctx, conf); err != nil {
		s.Bad("backup failed - nothing changed")
		return fixrun.Failed
	}

	// as_root cp "$new" "$conf" && as_root update-ca-certificates
	if err := s.AsRoot(ctx, "cp", work, conf); err != nil {
		s.Bad("could not install the edited file - restoring")
		f.restore(ctx, s, bak, conf, update)
		return fixrun.Failed
	}
	if err := s.AsRoot(ctx, update); err != nil {
		s.Bad("update-ca-certificates failed - restoring")
		f.restore(ctx, s, bak, conf, update)
		return fixrun.Failed
	}

	switch v := f.Paths.probeBundle(ctx, f.Paths.debianBundles()); v {
	case probe.VerdictRejected:
		s.OK("verified: the rebuilt system bundle rejects the compromised chain")
		s.Note("%s: backup at %s (restore with --undo)", conf, bak)
		return fixrun.Changed
	default:
		shown := string(v)
		if shown == "" {
			shown = "no result"
		}
		s.Bad("verification failed (%s) - rolling back", shown)
		f.restore(ctx, s, bak, conf, update)
		return fixrun.Failed
	}
}

// restore puts the backup back and rebuilds the bundle from it, as the script's
// `as_root cp -p "$bak" "$conf" && as_root update-ca-certificates`.
func (f *DebianLikeFix) restore(ctx context.Context, s *fixrun.Session, bak, conf, update string) {
	if err := s.Restore(ctx, bak, conf); err != nil {
		s.Bad("restore failed: %v - the backup is at %s", err, bak)
		return
	}
	_ = s.AsRoot(ctx, update)
}

// P11BlocklistFix ports fix_p11_blocklist (Fedora, RHEL, SUSE, Arch): it adds the
// two roots to the p11-kit blocklist as NEW files, writes a marker so --undo can
// tell them from anything else, and rebuilds the bundle. Nothing existing is edited.
type P11BlocklistFix struct {
	WorkaroundOnly bool
	Paths          Paths
}

func (f *P11BlocklistFix) Kind() string   { return "ospkg" }
func (f *P11BlocklistFix) Target() string { return "p11-kit blocklist" }

// blocklistDir ports the directory choice: the first trust-source root that
// exists, preferring "blocklist" and falling back to the older "blacklist".
func (p Paths) blocklistDir() string {
	for _, r := range p.roots() {
		if fi, err := os.Stat(r.Source); err != nil || !fi.IsDir() {
			continue
		}
		for _, d := range r.Dirs {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				return d
			}
		}
		return r.Dirs[0] // none exists yet: the first (blocklist) is created
	}
	return ""
}

func (f *P11BlocklistFix) Run(ctx context.Context, s *fixrun.Session) fixrun.Outcome {
	s.Say("%s  (Fedora/RHEL/SUSE/Arch)", s.Bold("p11-kit blocklist"))

	trust := f.Paths.which("trust")
	if trust == "" {
		s.Warn("'trust' command not found")
		return fixrun.Skipped
	}
	dir := f.Paths.blocklistDir()
	if dir == "" {
		s.Warn("no known trust-source directory")
		return fixrun.Skipped
	}
	if _, err := os.Stat(filepath.Join(dir, emSignFile)); err == nil {
		s.OK("already clean - blocklist entry exists in %s", dir)
		return fixrun.Skipped
	}
	s.Say("would add blocklist entries to %s (new files; nothing existing is modified)", dir)

	if s.DryRun {
		s.Cmd("trust extract --format=pem-bundle %s %s/%s", emSignQuery, dir, emSignFile)
		s.Cmd("trust extract --format=pem-bundle %s %s/%s", comodoQuery, dir, comodoFile)
		s.Cmd("update-ca-trust   # or update-ca-certificates on SUSE")
		return fixrun.Skipped
	}
	if !s.Confirm(fmt.Sprintf("Add the two roots to the trust blocklist in %s?", dir)) {
		s.Say("skipped")
		return fixrun.Skipped
	}
	if _, err := s.NeedRoot(dir); err != nil {
		return fixrun.Failed
	}

	rebuild := f.rebuildCommand()
	if err := s.AsRoot(ctx, "mkdir", "-p", dir); err != nil {
		s.Bad("could not create %s", dir)
		return fixrun.Failed
	}
	for _, e := range []struct{ query, file string }{{emSignQuery, emSignFile}, {comodoQuery, comodoFile}} {
		if err := s.AsRoot(ctx, trust, "extract", "--overwrite", "--format=pem-bundle", e.query, filepath.Join(dir, e.file)); err != nil {
			s.Bad("could not write %s - removing what was added", e.file)
			f.remove(ctx, s, dir, rebuild)
			return fixrun.Failed
		}
	}
	// printf 'created by emudhra-audit-fix.sh STAMP\n' | tee "$d/.emudhra-audit-created"
	if err := s.AsRoot(ctx, "sh", "-c", fmt.Sprintf("printf 'created by emudhra-audit-fix.sh %s\\n' > %q", s.Stamp, filepath.Join(dir, markerFile))); err != nil {
		s.Bad("could not write the marker file - removing what was added")
		f.remove(ctx, s, dir, rebuild)
		return fixrun.Failed
	}
	if rebuild != "" {
		if err := s.AsRoot(ctx, rebuild); err != nil {
			s.Bad("%s failed - removing the blocklist entries", filepath.Base(rebuild))
			f.remove(ctx, s, dir, rebuild)
			return fixrun.Failed
		}
	}

	switch v := f.Paths.probeBundle(ctx, f.Paths.p11Bundles()); v {
	case probe.VerdictRejected:
		s.OK("verified: the rebuilt bundle rejects the compromised chain")
		s.Note("blocklist files in %s (restore with --undo)", dir)
		return fixrun.Changed
	default:
		shown := string(v)
		if shown == "" {
			shown = "no result"
		}
		s.Bad("verification failed (%s) - removing the blocklist entries", shown)
		f.remove(ctx, s, dir, rebuild)
		return fixrun.Failed
	}
}

// rebuildCommand is update-ca-trust, or update-ca-certificates on SUSE.
func (f *P11BlocklistFix) rebuildCommand() string {
	if c := f.Paths.which("update-ca-trust"); c != "" {
		return c
	}
	return f.Paths.which("update-ca-certificates")
}

// remove ports remove_blocklist_files followed by the rebuild.
func (f *P11BlocklistFix) remove(ctx context.Context, s *fixrun.Session, dir, rebuild string) {
	if err := removeBlocklistFiles(ctx, s, dir); err != nil {
		return
	}
	if rebuild != "" {
		_ = s.AsRoot(ctx, rebuild)
	}
}

// removeBlocklistFiles ports remove_blocklist_files: delete the three files this
// program creates. It refuses unless dir is a non-empty absolute path to an
// existing directory, so an empty variable can never become `rm -f /emSign_...`.
func removeBlocklistFiles(ctx context.Context, s *fixrun.Session, dir string) error {
	if !strings.HasPrefix(dir, "/") || len(dir) < 2 {
		s.Bad("refusing to remove files: directory is empty or not absolute ('%s')", dir)
		return fmt.Errorf("not an absolute directory")
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		s.Bad("refusing to remove files: %s is not a directory", dir)
		return fmt.Errorf("not a directory")
	}
	return s.AsRoot(ctx, "rm", "-f", filepath.Join(dir, emSignFile), filepath.Join(dir, comodoFile), filepath.Join(dir, markerFile))
}

// Undo ports the system section of run_undo: restore the newest
// ca-certificates.conf backup and remove the blocklist entries this program
// created. Only a directory holding OUR marker is touched.
func (k *Kind) Undo(ctx context.Context, env *kinds.Env, s *fixrun.Session) error {
	return undoWith(ctx, s, Paths{PathEnv: env.Path()})
}

func undoWith(ctx context.Context, s *fixrun.Session, p Paths) error {
	for _, r := range p.roots() {
		for _, dir := range r.Dirs {
			if _, err := os.Stat(filepath.Join(dir, markerFile)); err != nil {
				continue
			}
			s.Say("%s", s.Bold(dir))
			s.Say("remove the blocklist entries this script added (%s, %s)", emSignFile, comodoFile)
			if s.DryRun {
				s.Say("[dry-run] would remove them and rebuild the bundle")
				continue
			}
			if !s.Confirm("Remove them and rebuild the trust bundle?") {
				s.Say("skipped")
				continue
			}
			if _, err := s.NeedRoot(dir); err != nil {
				continue
			}
			fix := &P11BlocklistFix{Paths: p}
			rebuild := fix.rebuildCommand()
			if err := removeBlocklistFiles(ctx, s, dir); err != nil {
				s.Bad("could not remove them")
				continue
			}
			if rebuild != "" {
				_ = s.AsRoot(ctx, rebuild)
			}
			s.OK("removed and rebuilt")
		}
	}

	conf := p.conf()
	bak := fixrun.NewestBackup(conf)
	if bak == "" {
		return nil
	}
	s.Say("%s", s.Bold(conf))
	s.Say("restore from %s", bak)
	if s.DryRun {
		s.Say("[dry-run] would restore it")
		return nil
	}
	if !s.Confirm(fmt.Sprintf("Restore %s from that backup?", conf)) {
		s.Say("skipped")
		return nil
	}
	if _, err := s.NeedRoot(conf); err != nil {
		return nil
	}
	if err := s.Restore(ctx, bak, conf); err != nil {
		s.Bad("restore failed")
		return nil
	}
	s.OK("restored")
	if u := p.which("update-ca-certificates"); u != "" {
		_ = s.AsRoot(ctx, u)
	}
	return nil
}
