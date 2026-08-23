# Driver instructions

- WDM x64, WDK-supported APIs, test-signing only.
- Validate IRP buffer lengths, struct `Size`, ABI version, transfer limit,
  overflow, RAM range, owner PID, write gate, and acknowledgement magic.
- Keep physical writes page-bounded and restore mappings immediately.
- No hidden devices, vulnerable-driver loaders, CI bypass, protection changes,
  arbitrary kernel-virtual writes, or undocumented concealment behavior.
- Update the shared ABI, user client, driver, and tests/docs as one atomic
  change.
