---
name: Bug report
about: Reproducible KDBG defect
title: "[BUG] "
labels: bug
assignees: ""
---

## Environment

- KDBG version:
- Main ZIP SHA-256:
- Symbols ZIP SHA-256:
- Windows build:
- VM/hypervisor and snapshot identifier:
- Backend:
- Driver ABI:
- Commit:
- Exact failing command:

## Reproduction

## Expected

## Actual

## PFN/PA

Use only fixture PFN in reports. Do not attach full memory pages containing private data.

## Logs

Run `tools/diagnose.ps1 -VerifyPackage`. Include its redacted output plus
requested/completed lengths and the verification result.

## Redaction confirmation

- [ ] I removed credentials, private paths, unrelated process memory, and raw
      memory pages that are not required to reproduce the defect.
- [ ] This report contains no exploit details. Security-sensitive reports go to
      https://github.com/yunttai/KDBG/security/advisories/new instead.
