# KDBG privacy and local-data policy

## No telemetry by default; no network telemetry

KDBG 1.1.0 has no automatic telemetry, analytics, update check, cloud upload,
or remote-control service. The base package does not require a network
connection. Optional tools or runtimes supplied by an operator have their own
privacy terms and are outside this package.

For an explicit performance run, setting `KDBG_RUNTIME_TELEMETRY` to an
absolute JSON path on a local fixed drive enables bounded runtime measurements.
Relative, UNC, device-namespace, mapped-network, removable-drive, and resolved
remote/reparse paths are rejected. The file contains frame interval/stall
counters and disjoint completed, partial, failed, and cancelled process-scan
aggregates covering regions, bytes, I/O failures, and cancellation latency. It
does not contain target memory bytes, process names, or filesystem paths, and
it is never uploaded by KDBG. Without that environment variable no runtime
telemetry writer starts.

Enabling succeeds only after KDBG durably writes the first JSON snapshot.
Subsequent snapshots use a process/session-unique sibling temporary file and a
write-through atomic replacement, so a failed update does not delete the last
good report. The local diagnostic `application.started` status is `0` when
telemetry was not requested, `1` after successful activation, and `2` through
`9` for a rejected configuration, unsafe path, initial write failure, writer
startup failure, or unsupported platform. Its native field carries a local
Win32 or filesystem error code when available; neither field contains a path.

## Data stored locally

KDBG may store UI configuration, address tables, snapshots, diagnostics,
evidence metadata, and crash dumps under the operator-selected evidence path
or `%LOCALAPPDATA%\KDBG`. Those files can contain process names, virtual or
physical addresses, bytes read from the fixture, local module paths, and system
metadata. They remain on the local machine unless the operator copies them.

The default uninstaller retains the extracted package and user data so a failed
upgrade can be diagnosed and rolled back. `tools/uninstall.ps1 -PurgePackage
-PurgeUserData` removes the selected package and KDBG user-data roots after the
helper exits. Operators must review the printed targets before using purge.

## Evidence and crash handling

Before sharing diagnostics or a DEF CON recording, redact private paths,
notifications, usernames, unrelated process names, unrelated memory bytes, and
credentials. Do not upload raw crash dumps or snapshots until their contents
have been reviewed. Keep evidence outside the immutable package directory and
apply the retention and deletion policy of the organization that collected it.

KDBG does not claim that third-party debuggers, symbol servers, hypervisors, or
MemProcFS components follow this policy. Consult their notices before enabling
them.
