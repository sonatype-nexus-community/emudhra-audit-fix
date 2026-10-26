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

# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

The tool is now a Go program. Behaviour is ported from the Bash script as it was at v0.9.0; where this list says "changed" it
is a difference you can see.

### Added

- A single static binary for macOS and Linux (amd64 and arm64), published by GoReleaser with a GPG-signed checksum file.
- `--list-kinds`, which lists every kind of audit and fix and whether it applies on this machine.
- `--version`.
- One package per kind of tool under `internal/kinds/`, with an explicit registry. Each kind reports whether it applies on the
  platform it runs on.
- Automated tests for every audit and every fixer, run on Linux and macOS in CI. Fixers are tested against real temporary files and
  stub tools, and each failure path (failing tool, still-trusted result, declined prompt, dry run, failing `sudo`, failed
  verification) is covered.
- The Sonatype Community banner, printed only on a terminal.

### Changed

- The Bash script moved to `legacy/emudhra-audit-fix.sh`, with a warning that it is no longer maintained.
- The fix runner escalates with `sudo` for one command at a time and never re-executes the binary under `sudo`.
- The system trust-store fix is one host-wide fix, planned when any finding asks for it, as the script did.
- `-v` no longer turns on debug logging; `-vv` does.
- Linux package-manager steps are never run unasked: the Debian-family fix edits `ca-certificates.conf` and updates it, and only
  prints the vendor upgrade command.

### Fixed

- The Java probe called every handshake failure "rejected"; an unreachable host is now inconclusive.
- Installs of the macOS system bundle and of a JDK's `cacerts` are atomic.
- The p11-kit blocklist fix now writes the marker `--undo` relies on.
- uv-managed Pythons are found where uv says they are (the script's `UV_PYTHON_DIR` and `UV_TOOLS_DIR` are not environment
  variables); launcher links that resolve inside an install are now saved and restored; a managed install must be under uv's
  Python directory; the newest installed patch is no longer reported as "still selected".
- The compact "Not installed / not applicable" line lists tools by name and leaves out kinds that only fix.

### Removed

- Make. Everything is plain `go` tooling.
- The test-only environment variables of the script (`EMUDHRA_JAVA_HOMES`, `EMUDHRA_NODE_BINS`, `EMUDHRA_AUDIT_ONLY`). Tests inject
  their environment instead.

## 0.9.0 - 2026-10-23

- Audit and upgrade uv-managed Pythons and uv tool environments (`--only=uvpython`, `--only=uvtools`).

## 0.8.0 - 2026-10-22

- `--fix --only=rustup` for official rustup installs.
- `--fix --only=uv` for standalone uv installs.

## 0.7.0 - 2026-10-22

- `--fix --only=node` for Node.js installed with nvm, including the `I AGREE` gate before removing an old version.

## 0.6.0 - 2026-10-22

- `--fix`, `--dry-run`, `--yes`, `--only` and `--undo`; compact default output with `-v` and `-vv`; git and pip probes; Java
  `cacerts` stop-gap; script renamed to `emudhra-audit-fix.sh`.
