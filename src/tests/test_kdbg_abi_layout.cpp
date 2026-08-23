#include "TestHarness.h"

#include "shared/KDbgIoctl.h"
#include "shared/KDbgProbeIoctl.h"

#include <cstddef>

void RunKDbgAbiLayoutTests(kdbg::test::TestRunner& runner) {
    KDBG_CHECK(runner, KDBG_ABI_VERSION == 6U);
    KDBG_CHECK(runner, KDBG_PROBE_ABI_VERSION == 1U);
    KDBG_CHECK(runner, KDBG_MAX_TRANSFER_SIZE == 1024U * 1024U);
    KDBG_CHECK(runner, KDBG_MAX_PHYSICAL_RANGES == 4096U);
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
        offsetof(KDBG_PROCESS_MEMORY_REQUEST, Data) == 40U);
    KDBG_CHECK(runner, sizeof(KDBG_TRANSLATE_RESPONSE) == 192U);
    KDBG_CHECK(runner, sizeof(KDBG_PROBE_INFO_RESPONSE) == 48U);
}
