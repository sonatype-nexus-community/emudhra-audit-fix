<!--

    Copyright (c) 2026-present Sonatype, Inc.

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

# eMudhra Audit & Fix

`emudhra-audit-fix.sh` checks the developer tools installed on a machine against the
[eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/), and prints guidance for fixing anything
affected. By default it is **read-only**. With `--fix` it can also apply the fixes it knows about, one confirmed change at
a time, with backups and automatic rollback.

## Contents

- [Background](#background)
- [Quick start](#quick-start)
- [How it decides](#how-it-decides)
- [Scope](#scope)
- [Reading the output](#reading-the-output)
- [Options and exit codes](#options-and-exit-codes)
- [Remediation guidance](#remediation-guidance)
- [Applying fixes (`--fix`)](#applying-fixes---fix)
- [Requirements and portability](#requirements-and-portability)
- [Safety](#safety)
- [Limitations](#limitations)
- [Keeping it current](#keeping-it-current)
- [Development](#development)
- [The Fine Print](#the-fine-print)

## Background

Eight intermediate CA certificates issued by eMudhra had their private keys incorrectly generated, so anyone can recover
them from the certificates. An attacker holding one of those keys could impersonate any website or service to a client
that still trusts the chain. The fix is distrust, shipped through browsers, operating systems, language runtimes and
trust-store packages.

Which of your tools are protected depends on which trust store each one uses (the OS keychain, a bundled CA list, a JDK
`cacerts`, and so on), so one machine often has a mix of protected and affected tools. This script finds out which is which.

The authoritative source is <https://emudhra.we-have-a-problem.com/>. The fixed versions in this script were taken from
that page as of 2026-10-22; check the page for updates.

## Quick start

```bash
./emudhra-audit-fix.sh              # compact audit with live TLS probes: one line per item
./emudhra-audit-fix.sh --no-network # version checks only (no connections)
./emudhra-audit-fix.sh -v           # the full report: path, version and probe result for every item
./emudhra-audit-fix.sh -vv          # also show the probe commands and raw TLS errors
./emudhra-audit-fix.sh --fix --dry-run  # show exactly what a fix would do; change nothing
./emudhra-audit-fix.sh --undo --dry-run # show which backups --undo would restore
./emudhra-audit-fix.sh --fix --dry-run --only=node  # preview upgrading an nvm-managed Node.js
```

No installation is needed. The script is a single file; make it executable with `chmod +x emudhra-audit-fix.sh` if required.

## How it decides

For each tool it finds, the script runs up to two checks.

1. **Live probe (authoritative).** The tool itself connects to two hosts that chain to the compromised intermediates, plus
   a control host (`https://github.com/`, chosen because it does not depend on either root the page says to distrust).
   - A TLS certificate error on the test hosts means the tool **rejects** the chain: protected.
   - A successful connection means the tool **trusts** the chain: affected.
   - If the control host also fails, the result is "inconclusive". This catches tools with no CA bundle, a proxy that
     intercepts TLS, or no network, so those failures are not mistaken for protection.
2. **Version check (explains why).** The tool's version is compared with the fixed releases listed on the page.

The probe wins when the two disagree. For example, Go on macOS can be older than the fixed release but still reject the
chain, because it uses the macOS system verifier, which already carries Apple's block. The script reports that as
protected, and lists the old version under "upgrade when convenient".

## Scope

| Tool | Live probe | Version check | Notes |
|---|---|---|---|
| curl | yes | no | The page lists no fixed curl version; it depends on the CA bundle in use. |
| git | yes (`git ls-remote`) | no | Uses the OS/curl bundle, so it can differ from other tools. Also reports `http.sslCAInfo` and `http.sslVerify=false`. |
| Go | yes | yes | Fixed in 1.26.10 and 1.27.3. |
| Python | yes (default store, `certifi` if installed, and `pip download`) | yes | Checks `certifi` >= 2026.10.19 and `pip` >= 26.2.2. Every interpreter found is checked. |
| Java (JDK/JRE) | yes, needs a `javac` somewhere on the machine | yes | Every install found is checked. Fixed in 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1. |
| Node.js | yes (and again with `--use-system-ca` when affected) | yes | Fixed in 22.23.4, 24.22.1, 26.12.1. `--fix --only=node` can upgrade nvm installs; see [Node.js via nvm](#nodejs-via-nvm---onlynode). |
| Deno | yes | yes | Fixed in 2.9.8. |
| Bun | yes | no | The page lists the fix as pending. |
| rustup | no | yes | Fixed in 1.29.2. |
| uv | no | yes | Fixed in 0.13.4. |
| pixi | no | yes | Fixed in 0.82.1. |
| mise | no | yes | Fixed in 2026.10.17. |
| Claude Code | no | yes | Fixed in 2.1.303. |
| Homebrew `ca-certificates` | yes (tests the bundle) | yes | Fixed in 2026-09-25_1. |
| System CA bundle files | yes (tests the file directly) | no | `/etc/ssl/cert.pem` and the usual Linux and BSD locations. |
| OS CA packages | no | yes | dpkg (Debian, Ubuntu), apk, pacman, and Fedora rpm. Other rpm distributions are reported without a verdict. |
| Electron apps (macOS) | no | yes | Reads the embedded Electron version from each app in `/Applications` and `~/Applications`. |

Installs are found through `PATH` and the common version managers and package managers: nvm, Volta, fnm, asdf, mise,
pyenv, SDKMAN, Homebrew, `/usr/lib/jvm`, `/Library/Java/JavaVirtualMachines` and similar locations.

### Not covered yet

- Rust crates inside your projects (`rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10 are the fixed versions).
- Perl `Mozilla::CA`, Composer `ca-bundle`, Elixir `castore` and Erlang `certifi`.
- Containers, per-project virtualenvs and `node_modules`.
- Electron apps on Windows and Linux.
- Windows hosts (the script is a Bash script for Unix-like systems).

### Environment overrides

With `-v` the report starts with a "CA-related environment" section listing variables that change which trust store a tool
uses. In the default output that section only appears when one of them is set or a warning applies
(`SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`,
`NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`). It warns about settings that disable verification
(`GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`). The probes inherit your environment, so results describe how
each tool behaves in your shell, which may differ from a clean login or from CI.

## Reading the output

By default the output is a compact summary: one line per item with its status, path and the main reason, one line for
all the tools that are not installed, a summary count, and one line of guidance per affected item. Use `-v` for the full
report described below.

```
[OK] Go go1.26.4  /usr/local/go/bin/go  - rejects the chain, but older than the fixed release (fixed in 1.26.10)
[AFFECTED] Node.js v24.16.0  ~/.nvm/versions/node/v24.16.0/bin/node  - trusts the compromised chain; also behind (fixed in 24.22.1)
```

With `-v`, each item gets a status line, then its path, version result and probe result.

| Status | Meaning |
|---|---|
| `AFFECTED` | The live probe connected to a host using the compromised chain. |
| `OK` | The live probe rejected the chain. |
| `LIKELY-AFFECTED` | No usable probe result, and the version is older than the fixed release. |
| `LIKELY-OK` | No usable probe result, and the version is at or above the fixed release. |
| `UNKNOWN` | Neither check gave an answer. |

At the end there is a summary count, followed by the remediation guidance.

## Options and exit codes

| Option | Effect |
|---|---|
| `--no-network` | Skip live probes and make no connections. Items that need a probe to resolve are reported as unknown. |
| `--no-guidance` | Do not print remediation guidance. |
| `-v`, `--verbose` | Full report: path, version and probe result for every item, the environment section and complete remediation guidance. |
| `-vv` | Everything in `-v`, plus each probe command and the raw TLS errors. |
| `--fix` | After the audit, offer to apply fixes, asking before each change. See [Applying fixes](#applying-fixes---fix). |
| `--dry-run` | With `--fix`: run every check and show every step, but change nothing. |
| `--yes` | With `--fix` or `--undo`: do not ask the ordinary y/N questions (for unattended use). It **never** answers the `I AGREE` prompt that guards deleting a Node.js version. |
| `--only=KIND` | With `--fix`: apply one kind of fix only: `brew`, `sys`, `java`, `macpip` or `node`. |
| `--workaround-only` | With `--fix`: skip mention of the vendor package upgrade on Linux. |
| `--undo` | Restore the backups made by `--fix`. |
| `-h`, `--help` | Show usage. |

| Exit code | Meaning |
|---|---|
| `0` | Nothing affected or likely affected. |
| `1` | At least one item is affected or likely affected. |
| `2` | Usage error, or the script could not create its temporary directory. |

The exit codes make the script usable from CI or device management tooling.

## Remediation guidance

Guidance is printed after the summary in two groups:

- **Affected, fix these first.** Each item gets commands matched to how it was installed (for example `nvm install ...`,
  `sdk install java ...`, `brew upgrade ...`).
- **Protected today, but older than the fixed release.** Upgrade when convenient.

Where a tool reads the operating system's CA bundle, the guidance also includes the page's platform workaround
(macOS, Debian and Ubuntu, Alpine, Fedora and RHEL family, openSUSE, Arch, NixOS, FreeBSD, NetBSD). Only the block for the
current platform is printed, and only if an affected item needs it.

Prefer upgrading over the workaround. The workaround removes two widely used roots (`AAA Certificate Services` and
`emSign ECC Root CA - G3`) from the trust store, which can break legitimate sites that chain to them, and an OS update may
replace the edited file. Java and Electron apps use their own trust lists, so OS-level workarounds do not help them; they
need an upgrade. Node.js uses its own bundled list by default; the script tests `--use-system-ca` and says whether it helps
on your machine. For a Node.js installed with nvm, `--fix --only=node` can do the upgrade for you (see
[Node.js via nvm](#nodejs-via-nvm---onlynode)).

If no fixed JDK build is available yet, the guidance for a Java install also prints a stop-gap: back up that JDK's
`cacerts` and delete the entries for the two roots. It makes Java reject sites chained to those roots, and is undone by
a JDK upgrade or by restoring the backup. `--fix --only=java` applies it for you, after testing it on a copy.

**Without `--fix` the script never runs any of this guidance.** It only prints it. Read each command before running it; the
trust-store commands need `sudo`.

After changing anything, run the script again to confirm.

## Applying fixes (`--fix`)

`--fix` changes the machine, so read this section before using it. **Prefer upgrading** the affected tool where a fixed
release exists; the fixes here distrust two roots, which has side effects.

### What it can fix

| Kind (`--only=`) | What it does | Needs sudo |
|---|---|---|
| `brew` | `brew update && brew upgrade ca-certificates` (an upgrade, not a trust-store edit). | no |
| `sys` | Removes the two roots from the system CA bundle: `/etc/ssl/cert.pem` on macOS; `ca-certificates.conf` plus `update-ca-certificates` on Debian, Ubuntu and Alpine; the p11-kit blocklist on Fedora, RHEL, SUSE and Arch (only Fedora tested). | yes |
| `java` | Deletes the two roots from a JDK's `cacerts`. A **stop-gap** for JDKs with no fixed build; a JDK upgrade restores them. | if the JDK is not yours |
| `macpip` | Appends the page's `PIP_CERT` line to Apple's Python `sitecustomize.py`. | yes |
| `node` | Upgrades a Node.js installed with **nvm** to the fixed release for its own major line (see below). An upgrade, not a trust-store edit. | no |

The two roots are `AAA Certificate Services` (Comodo/Sectigo) and `emSign ECC Root CA - G3`. Nothing else is removed. The
script refuses to proceed if a change would remove more than expected.

### Node.js via nvm (`--only=node`)

For a Node.js under `$NVM_DIR` (default `~/.nvm`) that is behind its fixed release, `--fix` runs
`nvm install v<fixed> --reinstall-packages-from=<old>`, where `<fixed>` is the fixed release for the **same major line**
(22.23.4, 24.22.1 or 26.12.1). It will not jump to another major, and it asks `nvm version-remote` first, so it refuses
cleanly if the fixed release is not published yet.

- One run covers a whole major line: if several old versions of it are installed, the fixed release is installed once.
- The new binary is probed afterwards and must reject the compromised chain; otherwise nothing else is changed, and
  no removal is offered.
- Making the new version your **default** is a separate prompt, offered only if the old version is currently your nvm
  default. Other projects may rely on it, so it is never switched silently. If the new binary fails verification, the
  default is not touched at all, even with `--yes`.
- **Removing the old, affected version is offered last, behind a deliberate gate.** After a verified upgrade, each older
  version on the same major line is offered for removal one at a time. Because this deletes something, it is not a
  `y/N` question: the script prints what will be lost (projects pinning that version through `.nvmrc`,
  `.node-version`, `engines` or CI scripts; global npm packages installed only under it; that new shells will no longer
  find it; that undoing it means reinstalling the vulnerable version) and you must type exactly `I AGREE`.
  - The answer is compared byte for byte: `y`, `yes`, `i agree`, `I agree`, a leading or trailing space, and empty
    input all cancel. **`--yes` never answers this
    prompt**, and with no terminal nothing is removed.
  - A version is **kept, with the reason shown**, if it is your current nvm default or if any nvm alias resolves to it.
    The version just installed, and any newer one, is never offered.
  - Each old version gets its own prompt; agreeing for one does not cover another.
  - nvm refuses to uninstall the version that is **currently active** in your shell, and a script started from a shell
    that still has the old version active inherits that. The script runs `nvm deactivate` and then `nvm uninstall` in
    its own subshell (your shell is not affected). If nvm still refuses, the script prints nvm's own message and tells
    you to open a new shell and run `nvm uninstall <old>`.
  - Prefer to do it yourself? Decline and run `nvm uninstall <old>` later in a shell that does not have it active.
- `nvm` is a shell function, so the script sources `nvm.sh` in a subshell; your shell and nvm configuration are not changed.
- Volta, fnm, asdf, mise and Homebrew Node are not handled yet; for those the audit prints the upgrade command.

### Safeguards

Each change follows the same sequence (Debian, Ubuntu, Alpine and Fedora differ slightly; see
[Known limitations](#known-limitations-of---fix)):

1. The new file or store is built on a **copy** first.
2. The copy is **tested**: it must reject the compromised chain, and it must still validate GitHub, Google, PyPI, Maven
   Central, npm and the Go module proxy. If a normal site would break, the change is refused.
3. You are **asked** (`--yes` skips the y/N question; with no terminal and no `--yes` nothing is changed). Deleting a
   Node.js version is the exception: it needs `I AGREE` typed on a terminal, and `--yes` cannot supply it.
4. The original is **backed up** next to itself as `<file>.pre-emudhra-<timestamp>`.
5. The change is installed, then the tool is **probed again**. If it does not reject the chain, the backup is restored
   automatically.

`--dry-run` stops before step 3 and prints the exact commands. `--undo` restores the newest backup for each store it
finds. `--undo` also removes the p11-kit blocklist files that `--fix` created. Homebrew upgrades are not covered by `--undo`.

### Side effects you should expect

- **Sites that chain to either root stop validating** in tools using the patched store. This is real: `example.com`
  currently chains to `AAA Certificate Services`. Check anything you depend on, such as internal or partner sites.
- **Updates can undo the change.** An OS update may replace `/etc/ssl/cert.pem`; a JDK upgrade restores the roots; an
  Xcode update replaces Apple's Python directory. Re-run the audit after updating.
- **Managed devices.** On a Mac enrolled in MDM the script warns you: IT may overwrite these edits or want to apply them
  centrally. The page does not recommend the Windows equivalent for enterprise-managed devices, and the same caution
  applies here.
- **It cannot patch what it cannot see**: Electron apps, bundled runtimes, containers and CI images need their own updates.

### What has been tested

| Path | Status |
|---|---|
| Root-stripping on a real macOS bundle (`tests/test_strip_roots.sh`) | Tested: exactly the two roots removed, all others unchanged by SHA-256. |
| Java `cacerts`: fix, verify, idempotence, `--undo`, rollback | Tested end to end on a throwaway JDK copy. Restoring gave a byte-identical file. |
| Debian 12 and Ubuntu 24.04 (`ca-certificates.conf`) | Tested in containers (`tests/test_linux_containers.sh`): affected, fixed, no-op on re-run, undone. |
| Alpine 3.18 | Tested in a container, same cycle. |
| Fedora 41 (p11-kit blocklist) | Tested in a container, same cycle. `--undo` removes only the files the script created. |
| OS package version checks (dpkg, apk, rpm) | Tested on Ubuntu, Debian, Alpine 3.18 and 3.20, and Fedora 41. |
| `--dry-run` on macOS for `sys`, `java`, `brew` and `macpip` | Tested. |
| The confirmation prompt under a real pseudo-terminal, and refusal with no terminal (`tests/test_confirm_prompt.sh`) | Tested. The test fails on the earlier code that lost the terminal. |
| Node.js via nvm: install, verify, default alias, declined prompts, failed install, unpublished fix, other major (`tests/test_fix_node.sh`) | Tested against a stub nvm with no network, including the `I AGREE` removal gate (exact match, `--yes`, no terminal, kept default and aliased versions, several old versions, failed uninstall, and nvm refusing to remove the active version). The deactivate-then-uninstall sequence was also checked against the real `nvm.sh` in a throwaway `NVM_DIR`. Mutation-checked: twelve deliberate breakages of the script (skipped verification, an unasked default change, a disabled no-fix guard, six ways of weakening the removal gate or its exclusions, per-binary planning, no deactivate, hidden nvm output) each make the tests fail. |
| Node.js via nvm on a real machine | One real `--fix --only=node` run on macOS with a real nvm: it upgraded 24.16.0 to 24.22.1, verified it, offered the old version for removal behind `I AGREE`, and removed it (after fixing a bug where nvm refused to remove the version active in the calling shell). One machine, one run: it is not covered by the automated tests. |
| `--yes` validation, bad flags | Tested. |
| The macOS system-bundle edit, `brew` upgrade and Java `cacerts` fix on a real machine | Applied on a real macOS machine (the backups and a follow-up audit confirm it): the affected items then report as protected. This is not covered by the automated tests. |
| The macOS `macpip` fix | **Not applied for real.** Dry run only. |
| openSUSE/SLES, Arch, NixOS, RHEL/CentOS/Rocky/Alma, Amazon Linux, FreeBSD, NetBSD | **Not tested.** The SUSE and Arch paths reuse the Fedora blocklist code with different directories. |
| Linux on x86-64 | Tested on arm64 containers only. |

Current distribution images already carry the vendor's fixed package, so the container tests first step
`ca-certificates` back to an older version to create the unpatched state. Run the dry run first on any machine, and expect
to read what it prints.

### Known limitations of `--fix`

- On Debian, Ubuntu, Alpine and Fedora the change is verified **after** it is installed (and rolled back if it fails),
  not on a copy beforehand. The macOS bundle and Java stores are tested on a copy first.
- `--undo` does not reverse a Homebrew upgrade.
- `--fix` needs the live probes to verify its work, so it cannot be combined with `--no-network`.
- The Alpine and Debian fixes disable the roots in `ca-certificates.conf`; a later `ca-certificates` package upgrade is the
  proper fix and replaces that file.

## Requirements and portability

- Bash 3.2 or later, which includes the stock macOS shell. The script avoids newer Bash features.
- Standard tools: `awk`, `sed`, `grep`, `readlink`, `mktemp`.
- Network access to `*.we-have-a-problem.com` and `github.com` for live probes. Use `--no-network` if that is not allowed.
- For the full set of probes, the relevant runtime must be installed. The script uses each tool's own runtime to test
  itself, so it does not need `jq` or any other extra dependency.
  - Java probes need a `javac` somewhere on the machine to compile the probe once. Without one, Java installs are
    checked by version only.
  - Testing CA bundle files and Homebrew's bundle uses a Python 3.8 or later interpreter found by the audit.

Tested on macOS (Apple silicon) with Bash 3.2, and on Debian 12, Ubuntu 24.04, Alpine 3.18/3.20 and Fedora 41 in arm64
containers. The BSDs, openSUSE, Arch, NixOS, RHEL-family distributions other than Fedora, and x86-64 Linux have **not** been
exercised; see [What has been tested](#what-has-been-tested). The macOS workaround edits `/etc/ssl/cert.pem`; reports
differ on whether macOS updates refresh that file, so re-run the audit after updating rather than assuming.

## Safety

- Without `--fix` the script is read-only. It does not install, change or delete anything on the machine. See
  [Applying fixes](#applying-fixes---fix) for what `--fix` does.
- It writes small probe programs (Python, Go, Java, Node.js, Deno, Bun) into a private temporary directory and removes it
  on exit. Go probes run with `GOTOOLCHAIN=local` so Go does not download another toolchain, and Python runs in isolated
  mode (`-I`).
- Live probes make ordinary HTTPS requests to the two test hosts published on the reference page and to `github.com`: a
  `GET /` from curl, Go, Python, Java, Node.js, Deno and Bun; `git ls-remote` (a `GET /info/refs`); and `pip download` for
  a package that does not exist (a `GET /simple/...`). They send no file contents.
- Without `--fix`, guidance is text only.

## Limitations

- **A probe shows what the tool does now.** A tool can be protected only because the OS already blocks the chain. The
  version column shows whether the tool itself has the fix.
- **Version checks are approximate.** Fixed versions came from the reference page and may change as vendors ship fixes. A
  `NO FIX for this release line` result means the page lists no fixed release on that line, such as an Electron 37 app.
- **Embedded runtimes cannot be probed.** Electron apps and tools such as rustup, uv, pixi, mise and Claude Code are
  version-checked only.
- **Per-project dependencies are not scanned.**
- The script reports the machine it runs on; it does not scan remote hosts.

## Keeping it current

The fixed versions are hard-coded near the check for each tool (search for `check_*_version`, `vcmp` and
`audit_simple` in `emudhra-audit-fix.sh`). When the page changes, for example when Bun or Erlang `certifi` ship a fix, update
those values and the `VERSION_OF_SCRIPT` number.

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

### Tests

```bash
tests/test_strip_roots.sh [BUNDLE]        # root-stripping logic against a real CA bundle (read-only)
tests/test_confirm_prompt.sh              # --fix prompt under a real pseudo-terminal, using a throwaway JDK copy
tests/test_fix_node.sh                    # --fix --only=node against a stub nvm (no network, ~8s, never touches ~/.nvm)
tests/test_linux_containers.sh [IMAGE...] # --fix and --undo cycles in throwaway Linux containers (needs Docker)
```

`test_confirm_prompt.sh` needs `python3` and a JDK with `keytool`. `test_linux_containers.sh` mounts the repository
read-only and removes each container afterwards.

Three environment variables exist **for tests only** and are not meant for normal use:

- `EMUDHRA_JAVA_HOMES` (space-separated paths) replaces JDK discovery, so a fix can be pointed at a copy instead of a
  real JDK.
- `EMUDHRA_NODE_BINS` does the same for Node.js.
- `EMUDHRA_AUDIT_ONLY=node` (or `curl`, `git`, `python`, ...) runs just that one audit, so a test of one fix does not
  wait on live probes of every other tool.

### Releasing

1. Update `VERSION_OF_SCRIPT` in `emudhra-audit-fix.sh`, and the fixed versions if the reference page has changed.
2. Run the tests above and check the README still matches the behaviour.
3. Commit, then tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
4. Create the GitHub release with `gh release create vX.Y.Z`, attaching `emudhra-audit-fix.sh`.

## The Fine Print

Remember:

This project is part of the [Sonatype Nexus Community](https://github.com/sonatype-nexus-community) organization, which is not officially supported by Sonatype. Please review the latest pull requests, issues, and commits to understand this project's readiness for contribution and use.

* File suggestions and requests on this repo through GitHub Issues, so that the community can pitch in
* Use or contribute to this project according to your organization's policies and your own risk tolerance
* Don't file Sonatype support tickets related to this project— it won't reach the right people that way

Last but not least of all - have fun!
