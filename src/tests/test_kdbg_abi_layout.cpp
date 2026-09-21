#include "TestHarness.h"

#include "core/memory/IMemoryBackend.h"
#include "shared/KDbgIoctl.h"
#include "shared/KDbgProbeIoctl.h"

#include <cstddef>

void RunKDbgAbiLayoutTests(kdbg::test::TestRunner& runner) {
    KDBG_CHECK(runner, KDBG_ABI_VERSION == 7U);
    KDBG_CHECK(runner, KDBG_PROBE_ABI_VERSION == 1U);
    KDBG_CHECK(runner, KDBG_MAX_TRANSFER_SIZE == 1024U * 1024U);
    KDBG_CHECK(runner, KDBG_MAX_PHYSICAL_RANGES == 4096U);
    KDBG_CHECK(
        runner,
        KDBG_VERSION_FLAG_WRITE_GATE_ONE_SHOT == 0x00000080U);
    KDBG_CHECK(
        runner,
        KDBG_VERSION_FLAG_PHYSICAL_PAGE_COMPARE_WRITE == 0x00000100U);
    KDBG_CHECK(runner, KDBG_PROBE_PAGE_SIZE == KDBG_PAGE_SIZE);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_READ_REQUEST, Data) == 24U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_WRITE_REQUEST, Data) == 32U);
    KDBG_CHECK(runner, sizeof(KDBG_SESSION_STATUS_RESPONSE) == 64U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_SESSION_STATUS_RESPONSE, LastPhysicalWriteStatus) ==
            48U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_SESSION_STATUS_RESPONSE, LastPhysicalWriteStage) ==
            52U);
    KDBG_CHECK(
        runner,
        offsetof(
            KDBG_SESSION_STATUS_RESPONSE,
            LastPhysicalWriteTransferred) == 56U);
    KDBG_CHECK(
        runner,
        KDBG_PHYSICAL_WRITE_STAGE_COMPLETE == 4U);
    KDBG_CHECK(
        runner,
        KDBG_PHYSICAL_WRITE_STAGE_COMPARING == 5U);
    KDBG_CHECK(
        runner,
        KDBG_PHYSICAL_WRITE_STAGE_READBACK == 6U);
    KDBG_CHECK(runner, KDBG_PHYSICAL_WRITE_STAGE_MAX == 6U);
    KDBG_CHECK(runner, KDBG_PHYSICAL_PAGE_RESULT_APPLIED == 1U);
    KDBG_CHECK(runner, KDBG_PHYSICAL_PAGE_RESULT_CONFLICT == 2U);
    KDBG_CHECK(runner, KDBG_PHYSICAL_PAGE_RESULT_FAILED == 3U);
    KDBG_CHECK(
        runner,
        KDBG_PHYSICAL_PAGE_STATUS_CONFLICT == 0xC0000059U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PROCESS_MEMORY_REQUEST, Data) == 40U);
    KDBG_CHECK(runner, sizeof(KDBG_TRANSLATE_RESPONSE) == 192U);
    KDBG_CHECK(runner, sizeof(KDBG_PROBE_INFO_RESPONSE) == 48U);
    KDBG_CHECK(
        runner,
        sizeof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_REQUEST) == 8232U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_REQUEST, ExpectedBefore) ==
            40U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_REQUEST, Desired) ==
            4136U);
    KDBG_CHECK(
        runner,
        sizeof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_RESPONSE) == 4136U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_RESPONSE, Status) == 28U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_RESPONSE, TransactionId) ==
            32U);
    KDBG_CHECK(
        runner,
        offsetof(KDBG_PHYSICAL_PAGE_COMPARE_WRITE_RESPONSE, Readback) ==
            40U);

    const kdbg::PhysicalPageCompareWriteResult transaction{};
    KDBG_CHECK(
        runner,
        transaction.outcome ==
            kdbg::PhysicalPageCompareWriteOutcome::Conflict);
    KDBG_CHECK(runner, transaction.transferred == 0U);
    KDBG_CHECK(
        runner,
        transaction.first_mismatch_offset ==
            KDBG_PHYSICAL_PAGE_NO_MISMATCH);
    KDBG_CHECK(runner, transaction.native_status == 0U);
    KDBG_CHECK(runner, transaction.readback.size() == KDBG_PAGE_SIZE);
}
