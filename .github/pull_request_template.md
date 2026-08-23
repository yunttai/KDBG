## Scope

## Requirement

Link rows from `docs/TRACEABILITY_MATRIX.md`.

## Validation

```text
python src/tools/verify_layout.py
python src/tools/validate_release.py --source-complete
cmake ...
ctest ...
```

## Live Memory Safety

- [ ] No live memory access
- [ ] Read-only live access
- [ ] Fixture-only live write
- [ ] Dedicated VM and snapshot
- [ ] Physical ranges validated
- [ ] Preflight/read-back retained
- [ ] No CI bypass/BYOVD

## License

- [ ] No third-party code
- [ ] MIT source with notice
- [ ] Out-of-process copyleft boundary
