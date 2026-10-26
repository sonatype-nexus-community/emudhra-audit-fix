<!--
    
    Copyright (c) 2019-present Sonatype, Inc.
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    
-->


# Architecture

How the Go implementation of `emudhra-audit-fix` is put together. The behaviour is a port of the legacy script
(`legacy/emudhra-audit-fix.sh`), kept "as is" where it was correct; the structure is new.

## Contents

- [Overview](#overview)
- [Package layout](#package-layout)
- [The Kind model](#the-kind-model)
- [Findings and status](#findings-and-status)
- [Reporting](#reporting)
- [Fixing](#fixing)
- [Privilege and prompts](#privilege-and-prompts)
- [Probing](#probing)
- [uv](#uv)
- [Testing](#testing)
- [Adding a Kind](#adding-a-kind)
- [Dependencies](#dependencies)

## Overview

A **Kind** is one class of tool or artifact the eMudhra advisory affects: `node`, `java`, `uv`, `sysbundle` and so on. Each
Kind is a package under `internal/kinds/` that owns its discovery, its audit and, if it has one, its fix. Nothing outside a
Kind knows how to find a JDK or what an nvm install looks like.

`cli.Execute` runs the whole thing: audit every applicable Kind, render the report, then (with `--fix`) ask every Kind that can
fix to plan, and run the fixes in a fixed order.

## Package layout

```
main.go                  entry point: flags, logging, banner, signal handling
internal/
  cli/                   hand-rolled flag parsing, validation, orchestration (audit, report, fix, undo)
  kinds/                 the Kind, Fixer, Undoer, Finding and Env types
    curl/ git/ golang/ python/ java/ node/ deno/ bun/ rustup/ uv/ pixi/ mise/ claudecode/
    brew/ sysbundle/ ospkg/ macpip/ electron/ uvpython/ uvtools/    one package per Kind
    versiononly/         the shared audit for tools that can only be version-checked
  registry/              the explicit list of Kinds, aliases for --only, report section titles
  report/                compact and verbose rendering, guidance, the header and CA-environment block
  fixrun/                the fix runner: Session, Fix, outcomes, backups, privilege helpers
  probe/                 TLS probe engine, verdicts, parsing and judging probe output
  advisory/              the two roots to distrust and the fixed-version tables
  discover/              PATH lookup, symlink resolution, de-duplication, candidate globs, "where from"
  version/               dotted-version parsing and comparison
  trust/                 PEM bundle helpers (strip the two roots, count, sanity-check)
  backup/                backup naming (FILE.pre-emudhra-STAMP) and lookup
  exec/                  command Runner (real and fake) with timeouts
  privilege/             sudo escalation and write-access checks
  prompt/                confirmations, read from /dev/tty
  platform/              OS, distribution, architecture and terminal detection (Host)
  uvenv/                 uv's directories, managed-Python and tool-environment helpers, backup and restore
  uvverify/              the checks both uv fixers run before and after an upgrade
  banner/ logging/       the TTY banner and slog setup
  boundaries/            a test that fails the build if code outside its owner runs commands, says "sudo" or opens /dev/tty
  testutil/              hermetic Env builders for tests
```

## The Kind model

```go
type Kind interface {
    ID() string                               // stable identifier: "uv", "java"
    Describe() string                         // one line, for --list-kinds
    Applicable(h platform.Host) Applicability // cheap: no network, no discovery
    Audit(ctx context.Context, env *Env) ([]Finding, error)
}

type Fixer interface {            // optional
    Kind
    FixOrder() int                // where this Kind's fixes run; use the kinds.Fix* constants
    Plan(ctx context.Context, env *Env, findings []Finding) ([]fixrun.Fix, error)
}

type Undoer interface {           // optional
    Kind
    Undo(ctx context.Context, env *Env, s *fixrun.Session) error
}
```

Two more optional interfaces shape the verbose report: `Absent` (what to say when the Kind found nothing, where the script's
wording is not "not found") and `SectionNoter` (a note under the Kind's section).

`Plan` is given **every** Kind's findings, because some fixes are triggered by another tool's audit: the system trust-store
fix by any finding that asks for it, the macOS pip fix by a Python finding, a uv Python upgrade by the Python audit. A Fixer
must therefore ignore findings that are not its own unless it is one of the sanctioned cross-Kind triggers. The registry tests
enforce this (`TestFixersIgnoreOtherKindsFindings`, `TestSanctionedCrossKindTriggers`).

A Kind whose fix needs a *target* rather than a flag (which uv Python minor line, which uv tool) is asked through
`Finding.Requests`, the port of the script's `plan_add KIND TARGET`. `kinds.RequestsFor` collects them, de-duplicates and keeps
the highest minimum version per target.

### Env

`kinds.Env` carries every dependency a Kind uses (command runner, probe engine, prompter, privilege escalator, logger, flags,
temp directory, backup store) so tests can substitute fakes. It reads variables through `Getenv`, `Path()` and `Home()`, which
honour an injected `Environ` map. A Kind must use those rather than `os.Getenv`, so a test never sees the real machine.

### Registry

`registry.All()` is an explicit list, not `init()` registration, in the script's audit order. `ByID`, `IDs` and `ExpandAliases`
(`--only=sys` is `sysbundle` plus `ospkg`) live beside it, as do the report section titles. Adding a Kind is one line there.

## Findings and status

A Finding records **facts**, and the verdict is derived from them in one place:

- `SetProbe(result, reason)`: what the live probe said (trusted, rejected, skipped, inconclusive).
- `SetVersion(version, fixed, check, note)`: how the version compares with the fixed release.
- `Finding.Status()`: AFFECTED, LIKELY-AFFECTED, OK, LIKELY-OK or UNKNOWN. The probe wins over the version.

Kinds never choose a status. The exit code (`report.ExitCode`) is 1 when any finding is AFFECTED or LIKELY-AFFECTED. A Kind
whose audit fails is reported as an UNKNOWN finding, never dropped: "this check broke" must not look like "this was fine".

Flags on the Finding drive shared behaviour: `NeedsSystemGuidance` and `NeedsPipGuidance` print the shared platform blocks once,
`HasFix` makes the report offer `--fix`, and `GuidanceCompact` and `GuidanceFull` hold the Kind's own remediation text (bare
text; the report adds the layout).

## Reporting

`report.Reporter` renders findings in the script's format: compact by default, full with `-v`, with probe commands at `-vv`. With
`-v` the report is grouped into one titled section per Kind (`registry.SectionTitle`), including the sections that found nothing.
The header, the CA-related environment block and the "Not installed / not applicable" list are the report's, not the Kinds'.
Output is plain when stdout is not a terminal.

## Fixing

`fixrun.Fix` is one planned change:

```go
type Fix interface {
    Kind() string
    Target() string
    Run(ctx context.Context, s *fixrun.Session) Outcome // Changed, Failed or Skipped
}
```

`fixrun.Session` is everything a fix may use: output helpers that match the script's wording (`Say`, `OK`, `Bad`, `Warn`, `Cmd`),
`Confirm` and `ConfirmAgree`, `NeedRoot`/`AsRoot`, `Backup`/`Restore`, notes for the end-of-run summary, and the outcome counts.
`cli.planFixes` collects each Fixer's plan and sorts by `FixOrder` (brew, system store, Java, macOS pip, Node, uv, uv Python, uv
tools, rustup), and `runFixes` runs them in that order. One failing fix does not stop the others.

Every fix follows the same sequence, and a dry run stops before the confirmation:

1. build the change on a copy and test it;
2. ask (`--yes` answers y/N questions; nothing answers `I AGREE` but a person at a terminal);
3. back up next to the original as `FILE.pre-emudhra-STAMP` (or, for uv, in a `.emudhra-backups` directory on the same filesystem);
4. install atomically, then probe again;
5. restore the backup if the probe still trusts the chain.

`--undo` calls `Undo` on every Kind that has one and restores the newest backups. Package-manager upgrades (Homebrew, uv, nvm)
are not undone.

## Privilege and prompts

- The binary never re-executes itself under `sudo`. A fix that needs root runs that one command through `Session.AsRoot`,
  with stdio attached so `sudo` prompts on the terminal itself. There is no credential warm-up.
- `privilege.Escalator` checks write access to decide whether `sudo` is needed at all.
- Prompts read `/dev/tty`, not stdin, so they work when input is piped. With no terminal and no `--yes`, the answer is no.
  `ConfirmAgree` needs the exact text `I AGREE`; `--yes` never supplies it, and neither does end of input.
- `internal/boundaries` is a test that enforces this: `os/exec` only in `internal/exec`, the `sudo` literal only in
  `internal/privilege`, `/dev/tty` only in `internal/prompt`.

## Probing

The probe engine connects to two hosts that chain to the compromised intermediates and to a control host (`https://github.com/`).
Tools that are probed through their own runtime (Python, Go, Java, Node.js, Deno, Bun, curl, git) print `ok URL` or `certerr URL`
lines, and `probe.JudgeOutput` turns them into a verdict:

- control fails: inconclusive (a proxy, no network or no CA bundle must not look like protection);
- any test host trusted: trusted (AFFECTED);
- all test hosts rejected: rejected (protected);
- anything else: inconclusive.

`kinds.ResultOf` maps a verdict to the result a Finding records.

## uv

Three Kinds cooperate. The `python` Kind audits every interpreter, including uv-managed ones and each uv tool environment (it asks
uv where they are, never guesses), and files `Requests`. `uvpython` upgrades a managed minor line (`uv python upgrade`) and
`uvtools` rebuilds a tool environment (`uv tool upgrade`). Both back up the complete original installs and links before running
uv, refuse a uv that is too old to download safely (`uvverify.Ready`), verify the result through every applicable TLS path
(`uvverify.Python`), and move the originals back if anything is wrong. `uvenv` holds what they share: uv's directories, link
matching, copying and restoring.

## Testing

- Unit tests use fakes (`exec.FakeRunner`, `probe.FakeEngine`, `privilege.FakeEscalator`, `prompt.FakePrompter`).
- Fixers are tested against **real** temporary files and directories and stub executables run through the real runner, and the
  tests assert side effects (the recorded `cp -p BACKUP FILE`, or the actual restored bytes) rather than only return values.
  The user's answer is YES in those tests, so a confirmation can never hide a missing guard.
- `testutil.NewTestEnvT` builds a hermetic Env: temporary `HOME` and `PATH`, no real tools. The registry's hermeticity test runs
  every Kind with an empty environment.
- Contract tests iterate `registry.All()`: unique IDs, descriptions, an ordered `FixOrder` for every Fixer, titles for every
  auditing Kind, and the cross-Kind rules above.
- A change to a safeguard is mutation-checked: break the guard on purpose and confirm a test fails.
- On macOS, temporary directories live under `/var`, a symlink to `/private/var`; tests that compare paths resolve them first.

## Adding a Kind

1. Create `internal/kinds/<tool>/` implementing `Kind` (and `Fixer` or `Undoer` if it fixes).
2. Test it with `testutil.NewTestEnvT` and fakes; if it fixes, test every failure path and assert side effects.
3. Register it with one line in `registry.All()`, and give it a section title in `registry` if it audits.
4. Run `go test ./...`. The contract tests tell you what you missed.

Use the shared helpers instead of rewriting them: `discover.Lookup`, `Candidates`, `Resolve` with a `discover.Seen` (audit each real
install once), `discover.WhereFrom` (nvm, brew, ... to choose the remedy), `version.Parse` and `GE` against `advisory`,
`probe.JudgeOutput`, and `Session.Backup` / `Restore`.

## Dependencies

Three direct dependencies, all checked against Sonatype's component data: `github.com/creack/pty` and
`github.com/stretchr/testify` (tests only) and `golang.org/x/sys`. There is no CLI framework and no semver library: the flag set
is small and flat, and fixed-version comparison is dotted-numeric. The Go toolchain is pinned to a release that is itself not
affected by the advisory.
