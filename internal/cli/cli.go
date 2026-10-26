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

// Package cli provides hand-rolled flag parsing and command orchestration.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/backup"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/exec"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/kinds"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/platform"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/privilege"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/probe"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/prompt"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/registry"
	"github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/internal/report"
)

// Options holds the parsed command-line options.
type Options struct {
	NoNetwork      bool
	NoGuidance     bool
	Verbose        int // 0=compact, 1=full detail, 2=with probe commands and raw TLS errors
	Fix            bool
	DryRun         bool
	Yes            bool
	Undo           bool
	Only           []string
	WorkaroundOnly bool
	ListKinds      bool
	ShowVersion    bool
	ShowHelp       bool
	ShowBanner     bool
}

// version and commit are set via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
)

// SetVersion sets the version and commit from ldflags.
func SetVersion(v, c string) {
	version = v
	commit = c
}

// getVersion returns the version string with commit if available.
func getVersion() string {
	if commit != "none" {
		return fmt.Sprintf("%s (commit: %s)", version, commit)
	}
	return version
}

// ParseFlags parses command-line arguments and returns validated Options.
// Returns an error for usage errors (exit code 2).
func ParseFlags(args []string, version string) (Options, error) {
	var opts Options

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--no-network":
			opts.NoNetwork = true
		case "--no-guidance":
			opts.NoGuidance = true
		case "-v", "--verbose":
			if opts.Verbose < 1 {
				opts.Verbose = 1
			}
		case "-vv":
			opts.Verbose = 2
		case "--fix":
			opts.Fix = true
		case "--dry-run":
			opts.DryRun = true
			opts.Fix = true
		case "--yes":
			opts.Yes = true
		case "--undo":
			opts.Undo = true
		case "--workaround-only":
			opts.WorkaroundOnly = true
		case "-h", "--help":
			opts.ShowHelp = true
		case "--version":
			opts.ShowVersion = true
		case "--list-kinds":
			opts.ListKinds = true
		default:
			// Handle --only=KIND or --only KIND
			if strings.HasPrefix(arg, "--only=") {
				onlyVal := strings.TrimPrefix(arg, "--only=")
				opts.Only = strings.Split(onlyVal, ",")
			} else if arg == "--only" {
				if i+1 >= len(args) {
					return opts, fmt.Errorf("--only requires a KIND argument")
				}
				i++
				opts.Only = strings.Split(args[i], ",")
			} else {
				return opts, fmt.Errorf("unknown option: %s", arg)
			}
		}
	}

	// Validation rules (matching the bash script, lines 98-107)
	if err := validateOptions(&opts); err != nil {
		return opts, err
	}

	// Show banner when printing to TTY and not showing help/version in quiet mode
	opts.ShowBanner = !opts.ShowHelp && !opts.ShowVersion && !opts.ListKinds

	return opts, nil
}

// validateOptions checks for mutually exclusive or invalid flag combinations.
func validateOptions(opts *Options) error {
	// --undo cannot be combined with --fix (unless --dry-run)
	if opts.Undo && opts.Fix && !opts.DryRun {
		return fmt.Errorf("--undo cannot be combined with --fix")
	}

	// --only must be one of the known kinds
	validOnly := []string{"", "brew", "sys", "java", "macpip", "node", "uv", "uvpython", "uvtools", "rustup"}
	for _, kind := range opts.Only {
		if !slices.Contains(validOnly, kind) {
			return fmt.Errorf("--only must be one of: brew, sys, java, macpip, node, uv, uvpython, uvtools, rustup")
		}
	}

	// --yes only makes sense with --fix or --undo
	if opts.Yes && !opts.Fix && !opts.Undo {
		return fmt.Errorf("--yes only makes sense with --fix or --undo")
	}

	// --fix needs the live probes to verify its changes
	if opts.Fix && opts.NoNetwork {
		return fmt.Errorf("--fix needs the live probes to verify its changes; do not combine it with --no-network")
	}

	return nil
}

// Execute runs the main command logic and returns the exit code (0, 1, or 2).
// This ports the main orchestration from the bash script.
func Execute(ctx context.Context, opts Options, logger *slog.Logger) int {
	// Handle --version
	if opts.ShowVersion {
		// Version string is passed via -ldflags at build time
		// This prints: emudhra-audit-fix version X.Y.Z (commit: abc123)
		fmt.Printf("emudhra-audit-fix version %s\n", getVersion())
		return 0
	}

	// Handle --help
	if opts.ShowHelp {
		printUsage()
		return 0
	}

	// Handle --list-kinds
	if opts.ListKinds {
		return listKinds(logger, opts.Verbose)
	}

	// Build the environment for audit/fix/undo
	host := platform.Detect()
	env := buildEnv(host, opts, logger)

	// A private scratch directory for probe sources and patched copies, removed
	// on exit (the script's TMP=$(mktemp -d) and its EXIT trap). Without it a
	// Kind writing a probe file would put it in the current directory.
	tmp, cleanup, err := scratchDir()
	if err != nil {
		logger.Error("could not create a temporary directory", "error", err)
		return 2
	}
	defer cleanup()
	env.TempDir = tmp

	// Handle --undo
	if opts.Undo {
		printHeader(ctx, env, report.NewReporter(opts.Verbose, false), opts, os.Stdout)
		return runUndo(ctx, env, os.Stdout, host.HasTTY, registry.All(), opts)
	}

	reporter := report.NewReporter(opts.Verbose, opts.NoGuidance)
	reporter.Host = host
	reporter.Color = host.HasTTY
	reporter.Home = env.Home()
	reporter.FixMode = opts.Fix
	printHeader(ctx, env, reporter, opts, os.Stdout)

	// Perform audit
	findings, _, err := performAudit(ctx, env, logger, registry.All(), opts.Only)
	if err != nil {
		logger.Error("Audit failed", "error", err)
		return 2
	}

	// Render report
	reporter.Sections = buildSections(env, registry.All(), opts.Only, findings)
	reporter.Missing = missingTitles(reporter.Sections, findings)
	if err := reporter.Report(findings); err != nil {
		logger.Error("Report failed", "error", err)
		return 2
	}

	// Handle --fix
	if opts.Fix {
		runFixes(ctx, env, os.Stdout, host.HasTTY, registry.All(), findings, opts)
	}

	// Return exit code based on findings
	return report.ExitCode(findings)
}

// buildEnv constructs the Env for audit/fix/undo operations.
func buildEnv(host platform.Host, opts Options, logger *slog.Logger) *kinds.Env {
	return &kinds.Env{
		Host:           host,
		Run:            exec.NewRealRunner(),
		Probe:          probe.NewRealEngine(),
		Prompt:         prompt.NewRealPrompter(host.HasTTY),
		Priv:           privilege.NewRealEscalator(),
		Log:            logger,
		DryRun:         opts.DryRun,
		Yes:            opts.Yes,
		Offline:        opts.NoNetwork,
		WorkaroundOnly: opts.WorkaroundOnly,
		Backup:         backup.NewFileStore(),
	}
}

// performAudit runs the audit for every applicable Kind, or only the Kinds
// named by --only. It returns the findings, and the names of Kinds that were
// skipped or found nothing (the script's "Not installed / not applicable").
// A Kind whose Audit fails is reported as an UNKNOWN finding, never dropped:
// "this check broke" must not look like "this check was fine".
func performAudit(ctx context.Context, env *kinds.Env, logger *slog.Logger, all []kinds.Kind, only []string) ([]kinds.Finding, []string, error) {
	var allFindings []kinds.Finding
	var missing []string

	wanted := map[string]bool{}
	for _, id := range registry.ExpandAliases(only) {
		if id != "" {
			wanted[id] = true
		}
	}

	for _, kind := range all {
		if len(wanted) > 0 && !wanted[kind.ID()] {
			continue
		}
		app := kind.Applicable(env.Host)
		if !app.Applies {
			logger.Debug("Kind not applicable", "kind", kind.ID(), "reason", app.Reason)
			missing = append(missing, kind.ID())
			continue
		}

		logger.Debug("Auditing kind", "kind", kind.ID())
		findings, err := kind.Audit(ctx, env)
		if err != nil {
			logger.Error("Audit failed for kind", "kind", kind.ID(), "error", err)
			f := kinds.NewFinding(kind.ID(), kind.ID())
			f.SetProbe(kinds.ProbeInconclusive, "the check failed: "+err.Error())
			allFindings = append(allFindings, f)
			continue
		}
		if len(findings) == 0 {
			missing = append(missing, kind.ID())
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, missing, nil
}

// printHeader writes the opening lines and the CA-related environment, as the script does before
// any audit or undo.
func printHeader(ctx context.Context, env *kinds.Env, r *report.Reporter, opts Options, out io.Writer) {
	r.Output = out
	r.Color = env.Host.HasTTY
	flags := "-sm"
	if opts.Verbose >= 1 {
		flags = "-srm"
	}
	uname := strings.TrimSpace(env.Run.Run(ctx, "uname", flags).Stdout)
	v := version
	r.PrintHeader(report.Header{
		Version:    v,
		Uname:      uname,
		Now:        time.Now(),
		NoNetwork:  opts.NoNetwork,
		ProbeHosts: strings.Join(probe.BAD_URLS, " ") + " (control: " + probe.CONTROL_URL + ")",
	})
	if !opts.Undo {
		r.PrintEnvironment(env.Getenv)
	}
}

// buildSections lists, in audit order, the sections of the verbose report: every Kind that has a
// section title and was not filtered out by --only, with the wording for when it found nothing.
func buildSections(env *kinds.Env, all []kinds.Kind, only []string, findings []kinds.Finding) []report.Section {
	wanted := map[string]bool{}
	for _, id := range registry.ExpandAliases(only) {
		if id != "" {
			wanted[id] = true
		}
	}
	var secs []report.Section
	for _, k := range all {
		title := registry.SectionTitle(k.ID())
		if title == "" || (len(wanted) > 0 && !wanted[k.ID()]) {
			continue
		}
		sec := report.Section{ID: k.ID(), Title: title, None: "not found"}
		if a, ok := k.(kinds.Absent); ok {
			sec.None = a.AbsentText(env)
		}
		if n, ok := k.(kinds.SectionNoter); ok {
			sec.Note = n.SectionNote(env)
		}
		secs = append(secs, sec)
	}
	return secs
}

// missingTitles is the compact report's "Not installed / not applicable" list: the titles of the
// sections that found nothing.
func missingTitles(secs []report.Section, findings []kinds.Finding) string {
	var absent []string
	for _, sec := range secs {
		if !hasFindings(findings, sec.ID) {
			absent = append(absent, sec.Title)
		}
	}
	return strings.Join(absent, ", ")
}

func hasFindings(findings []kinds.Finding, id string) bool {
	for _, f := range findings {
		if f.Kind == id {
			return true
		}
	}
	return false
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: emudhra-audit-fix [options]

Audit of developer tools (curl, git, Go, Python, Java, Node.js, Deno, Bun, rustup, uv,
pixi, mise, Claude Code, Electron apps, Homebrew and OS CA bundles) against the eMudhra
intermediate CA compromise. By default it is read-only: it prints remediation guidance
for anything affected and changes nothing.

Audit options (the default output is a compact summary; use -v for the full report):
  --no-network      skip live TLS probes; version checks only
  --no-guidance     do not print remediation guidance
  -v, --verbose     full detail: path, version and probe result for every item, full guidance
  -vv               also print the probe commands that are run, and raw TLS errors

Fix options (these can modify the system; sudo is used where needed):
  --fix             after the audit, offer to apply fixes, asking before each change
  --dry-run         with --fix: verify and show every step but change nothing
  --yes             with --fix: do not ask before each change
  --workaround-only with --fix: skip the vendor package upgrade on Linux and go straight
                    to blocking the two roots
  --only=KIND       with --fix: apply only one kind of fix: brew, sys, java, macpip, node, uv, uvpython, uvtools or rustup
  --undo            restore system/JDK backups (uv upgrades excluded; asks first)

  -h, --help        show this help
  --version         show version
  --list-kinds      list all audit/fix kinds and their applicability
`)
}

// listKinds prints all registered kinds and their applicability.
func listKinds(logger *slog.Logger, verbose int) int {
	host := platform.Detect()

	fmt.Println("Available audit/fix kinds:")
	fmt.Println()

	for _, kind := range registry.All() {
		app := kind.Applicable(host)

		// Format: ID - Description [status]
		status := "applicable"
		if !app.Applies {
			status = fmt.Sprintf("not applicable (%s)", app.Reason)
		}

		fmt.Printf("  %-15s %s", kind.ID(), kind.Describe())
		if verbose >= 1 {
			fmt.Printf(" [%s]", status)
		}
		fmt.Println()

		if verbose >= 1 && !app.Applies {
			fmt.Printf("                  Reason: %s\n", app.Reason)
		}
	}

	return 0
}

// scratchDir creates the private scratch directory and returns it with the
// function that removes it. os.MkdirTemp makes it mode 0700.
func scratchDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "emudhra-")
	if err != nil {
		return "", func() {}, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}
