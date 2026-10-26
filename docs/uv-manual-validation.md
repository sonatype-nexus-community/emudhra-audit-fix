# Manual validation of uv environment coverage

The development tests use disposable directories. The commands below
are for the machine you want to audit and, only after reviewing the previews, update.

## Compare inventory

```bash
uv python list --only-installed --all-versions --managed-python
uv tool list --show-paths --show-python --show-version-specifiers --show-with --show-extras
./emudhra-audit-fix --no-network -v
```

Expect every unique managed interpreter to appear in the Python section, including versions without a PATH alias.
Multiple aliases for one interpreter produce one result. Installed tool environments appear as `uv tool: NAME Python`.
Two tools using the same interpreter must still get separate results. Broken environments appear as unknown.

The offline audit checks installed certifi and pip versions but does not make TLS connections or upgrade anything.
Native tools may have a Python environment without certifi or pip. They can therefore be unknown in this version only
check. Their application specific TLS implementation is outside the Python probes.

## Run the live audit

```bash
./emudhra-audit-fix -v
```

Inspect the default trust store, certifi, and pip result for each tool. A missing pip module is normal in many uv tool
environments. A control host failure must appear as inconclusive. The audit does not install missing packages.
The live audit can take several minutes when many interpreters and tools are installed.

## Review the planned changes

```bash
./emudhra-audit-fix --fix --dry-run --only=uvpython
./emudhra-audit-fix --fix --dry-run --only=uvtools
```

Both commands perform the full host audit, as the existing fix modes do. `--only` filters the fix phase.
The fix commands require stable uv `0.13.4` or later. An older, prerelease, or unrecognized version must be refused
before any upgrade. Update uv through its installation manager first.

Expect affected environments, known outdated trust packages, and available managed Python patches to produce offers.
Live rejection still produces a protected security verdict. Patch availability is reported separately. An empty plan
prints the discovered environment count and explains that no automatic upgrade was scheduled.
Retained older patches must not repeatedly schedule an upgrade already installed in the same interpreter family. The Python command must request an existing minor version such as `3.14`. The tool command must
name a specific tool, retain the same Python minor version, and disable interpreter downloads. There should be no
bulk `uv tool upgrade --all`, no forced version pin changes, and no direct pip modification of a tool environment.

A preview cannot know the final dependency versions because it does not run the resolver. Historical executable
directories, conflicting entrypoints, or unsupported interpreter configurations are refused with a reason.

## Apply selective fixes after reviewing the previews

```bash
./emudhra-audit-fix --fix --only=uvpython
./emudhra-audit-fix --fix --only=uvtools
```

Each proposed change asks for confirmation. Review the printed Python version, tool name, and backup location.
Python upgrades retain older patch versions and back up any same patch build they might replace. Tool upgrades can update the application and its dependencies within recorded
constraints. Do not run another uv install or upgrade concurrently.

Success requires TLS verification of all applicable Python trust paths and fixed versions of any installed certifi
and pip. Managed Python must also reach the previewed patch target, and existing standard launchers must select the verified interpreter. Tool success also requires consistent package
dependencies. A failed verification moves the saved originals and links back into place. Successful upgrades keep
private recovery transactions on the installation filesystem. Tool backups are beside the tool directory to avoid
uv tool listing warnings. Keep successful upgrade backups until you have exercised the tool commands you use. `--undo` does not reverse successful uv upgrades.

## Verify the result

```bash
uv python list --only-installed --all-versions --managed-python
uv tool list --show-paths --show-python --show-version-specifiers --show-with --show-extras
./emudhra-audit-fix -v
```

Compare inventory and pins with the first output. Run the ordinary workflows for any upgraded tools. The Python TLS
checks do not exercise an application's own network client or bundled native binaries.

Old retained Python patches can remain affected. Environments pinned to them need separate review. A successful Python
upgrade does not prove those old installations are protected.

Exit status 1 means the audit found at least one affected or likely affected item. During a fix run that audit precedes
the changes, so use the final changed/failed counts and the following audit to assess the outcome. Exit status 2 is a
usage error or failure to create the temporary directory.
