import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class VerifiedPageTransactionSourceTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_abi_is_fixed_size_append_only_v7(self) -> None:
        header = self.read("src/shared/KDbgIoctl.h")
        self.assertIn("#define KDBG_ABI_VERSION          7u", header)
        self.assertIn("IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE", header)
        self.assertIn(
            "sizeof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_REQUEST) == 8232u",
            header,
        )
        self.assertIn(
            "sizeof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_RESPONSE) == 4136u",
            header,
        )
        self.assertIn("ExpectedBefore[KDBG_PAGE_SIZE]", header)
        self.assertIn("Desired[KDBG_PAGE_SIZE]", header)
        self.assertIn("Readback[KDBG_PAGE_SIZE]", header)

    def test_driver_locks_before_fresh_range_validation_and_io(self) -> None:
        driver = self.read("src/driver/KDbgDriver/Driver.cpp")
        legacy = driver[driver.index(
            "case IOCTL_KDBG_WRITE_PHYSICAL"
        ):driver.index("case IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE")]
        legacy_lock = legacy.index("PhysicalTransactionLock")
        legacy_snapshot = legacy.index("PhysicalRangeSnapshot write_ranges")
        legacy_range = legacy.index("IsPhysicalRamRange(")
        legacy_consume = legacy.index("InterlockedCompareExchange(")
        legacy_write = legacy.index("WriteValidatedPhysicalRange(")
        self.assertLess(
            legacy_lock,
            legacy_snapshot,
            "legacy physical write must snapshot RAM only after locking",
        )
        self.assertLess(legacy_snapshot, legacy_range)
        self.assertLess(legacy_range, legacy_consume)
        self.assertLess(legacy_consume, legacy_write)

        handler = driver[driver.index(
            "case IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE"
        ):driver.index("case IOCTL_KDBG_GET_PROCESS_CONTEXT")]
        transaction_lock = handler.index("PhysicalTransactionLock")
        snapshot = handler.index("PhysicalRangeSnapshot write_ranges")
        range_validation = handler.index("IsPhysicalRamRange(")
        consume = handler.index("InterlockedCompareExchange(")
        baseline_read = handler.index("ReadPhysicalWithSnapshot(")
        write = handler.index("WriteValidatedPhysicalRange(")
        readback = handler.index("ReadPhysicalWithSnapshot(", baseline_read + 1)
        self.assertLess(transaction_lock, snapshot)
        self.assertLess(snapshot, range_validation)
        self.assertLess(range_validation, consume)
        self.assertLess(consume, baseline_read)
        self.assertLess(baseline_read, write)
        self.assertLess(write, readback)
        self.assertIn("pages.Expected()", handler)
        self.assertIn("pages.Desired()", handler)
        self.assertIn("KDBG_PHYSICAL_PAGE_RESULT_CONFLICT", handler)
        self.assertIn("KDBG_PHYSICAL_PAGE_RESULT_FAILED", handler)

    def test_backend_requires_and_strictly_validates_capability(self) -> None:
        backend = self.read("src/core/memory/KDbgBackend.cpp")
        self.assertGreaterEqual(
            backend.count("KDBG_VERSION_FLAG_PHYSICAL_PAGE_COMPARE_WRITE"),
            1,
        )
        method = backend[backend.index(
            "KDbgBackend::CompareWritePhysicalPage("
        ):backend.index("KDbgBackend::GetProcessContext(")]
        self.assertIn("response->TransactionId == transaction_id", method)
        self.assertIn("response->PhysicalAddress == physical_address", method)
        self.assertIn("response->Length == KDBG_PAGE_SIZE", method)
        self.assertIn("PhysicalPageCompareWriteOutcome::Conflict", method)
        self.assertIn("PhysicalPageCompareWriteOutcome::Failure", method)
        self.assertIn("readback.end(), desired.begin()", method)


if __name__ == "__main__":
    unittest.main()
