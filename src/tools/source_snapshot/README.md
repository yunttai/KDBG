# Canonical source snapshots

`source_snapshot.py` creates a deterministic source manifest from an explicit,
checked-in scope. It does not infer release completeness and does not change a
release gate by itself.

Generate artifacts outside the selected source tree:

```powershell
python .\src\tools\source_snapshot\source_snapshot.py generate `
  --root . `
  --scope .\src\tools\source_snapshot\scope.kdbg.json `
  --manifest .\out\release-epoch\SOURCE-SHA256SUMS.txt `
  --metadata .\out\release-epoch\SOURCE-MANIFEST.json
```

Verify an archived tree against those exact artifacts:

```powershell
python .\src\tools\source_snapshot\source_snapshot.py verify `
  --root .\out\release-epoch\source `
  --scope .\src\tools\source_snapshot\scope.kdbg.json `
  --manifest .\out\release-epoch\SOURCE-SHA256SUMS.txt `
  --metadata .\out\release-epoch\SOURCE-MANIFEST.json
```

Assert that two trees have identical selected bytes and paths:

```powershell
python .\src\tools\source_snapshot\source_snapshot.py assert-equal `
  --before-root .\out\release-epoch\source `
  --after-root . `
  --scope .\src\tools\source_snapshot\scope.kdbg.json
```

The manifest is UTF-8 with LF endings, a final LF, lowercase SHA-256 values,
POSIX relative paths, and ordinal path ordering. The companion JSON binds the
exact manifest digest and record count to both `scope_version` and the raw
scope-file SHA-256. `verify` rejects missing, extra, or content-changed selected
files. Exit code zero is the only successful assertion; `generate` reports
`GENERATED`, not `PASS`.

Run the standalone synthetic tests with:

```powershell
python -m unittest discover -s .\src\tools\source_snapshot -p "test_*.py" -v
```
