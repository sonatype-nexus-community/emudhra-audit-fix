# How to contribute

It's great you're here and reading this guide, because we need volunteers to help keep this project active and alive for the greater benefit of everyone!

- [Engaging with this project](#engaging-with-this-project)
- [Develpoment Guidelines](#develpoment-guidelines)
  - [Coding Conventions](#coding-conventions)
- [Testing](#testing)
- [Submitting Contributions](#submitting-contributions)

## Engaging with this project

Here are some important resources:
- [GitHub Issues](https://github.com/sonatype-nexus-community/emudhra-dev-tools-fixer/issues) - a place for bugs to be raised and feature requests made
- [The advisory](https://emudhra.we-have-a-problem.com/) - the source of the fixed versions

## Development Guidelines

Start with [ARCHITECTURE.md](./ARCHITECTURE.md): it explains the Kind model, which is where nearly every change goes.

You need the Go toolchain named in `go.mod`. Do not use an older 1.26 release: they are affected by the advisory this tool
audits. Everything is plain Go tooling, with no Makefile:

```bash
go build ./...
go vet ./...
go test ./...
```

The CI checks on every pull request are the same, plus `golangci-lint` (v2.13.2, configuration in `.golangci.yml`), tests on
Linux and macOS, and a Sonatype Lifecycle evaluation of the dependencies. A pull request needs all of them green. Releases are
built and signed by GoReleaser from a `v*` tag; contributors do not need to do anything for that.

A maintainer reviews pull requests as time allows; this is a community project and there is no response-time commitment.

### Coding Conventions

- Commits are signed, and signed off. In order to help verify the authenticity of contributed code, we ask that your
  [commits be signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
  All commits must be signed off to show that you agree to publish your changes under the current terms and licenses of the project.

  Here are some notes we found helpful in configuring a local environment to automatically sign git commits:
    - [GPG commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#gpg-commit-signature-verification)
    - [Telling Git about your GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key#telling-git-about-your-gpg-key)

- Format with `gofmt`. Keep the Apache licence header on every Go file.
- Write code like the code around it: its naming, its comment density, its idioms.
- Use the standard library where it is enough. A new dependency needs a reason and must pass a Sonatype component check
  (no known vulnerabilities, acceptable licence).
- Follow the boundaries: run commands only through `exec.Runner`, say `sudo` only in `internal/privilege`, open `/dev/tty` only
  in `internal/prompt`. `go test ./...` fails if you don't.
- Read environment variables and the home directory through `kinds.Env` (`Getenv`, `Path`, `Home`), never `os.Getenv`, so tests
  stay hermetic.
- A fix must be safe to run twice, ask before it changes anything, back up what it changes, verify the result and put the
  original back if verification fails. Copy the shape of an existing fixer.
- Fixed versions come from <https://emudhra.we-have-a-problem.com/>. Cite the page when you change them.

## Testing

Tests must not depend on the machine they run on: no network, no `sudo`, and no reading or writing outside temporary
directories. `testutil.NewTestEnvT(t)` builds an environment with a temporary `HOME` and `PATH` and no real tools; put stub
executables in that `PATH` and run them through the real runner when you want a fixer to run real commands.

- Test **side effects**, not just return values: the backup that was made, the bytes that were restored, the command that was
  (or was not) run.
- Answer YES to the confirmation in fixer tests, so a prompt can never hide a missing guard.
- Cover every failure path of a fixer: the tool fails, the result still trusts the chain, the user declines, it is a dry run,
  `sudo` fails, and verification fails after the change.
- Mutation-check a new safeguard: break it on purpose and confirm a test fails. A test that passes with the guard removed does
  not protect it.
- On macOS, temporary directories are under `/var`, a symlink to `/private/var`. Resolve them (`filepath.EvalSymlinks`) before
  comparing paths.
- Tests of the legacy Bash script are in `legacy/tests/`. The script is not maintained; do not extend them.

## Submitting Contributions

Please send Pull Requests that:
1. Have a singular purpose, and that is backed by one or more GitHub Issues in this project
2. Are clear
3. Have appropriate test coverage for the Pull Requests purpose
4. Meet our code style conventions (see [above](#coding-conventions))
5. Sign off your commits to show that you agree to publish your changes under the current terms and licenses of the project, and to indicate agreement with [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
