#include "TestHarness.h"

#include <iostream>

void RunPfnAddressTests(kdbg::test::TestRunner& runner);
void RunAddressWatchDurabilityTests(kdbg::test::TestRunner& runner);
void RunPageTableTests(kdbg::test::TestRunner& runner);
void RunPageSessionTests(kdbg::test::TestRunner& runner);
void RunProcessMemorySessionTests(kdbg::test::TestRunner& runner);
void RunPersistenceMigrationTests(kdbg::test::TestRunner& runner);
void RunScannerTests(kdbg::test::TestRunner& runner);
void RunAdvancedCoreTests(kdbg::test::TestRunner& runner);
void RunKDbgAbiLayoutTests(kdbg::test::TestRunner& runner);
void RunKernelModuleTests(kdbg::test::TestRunner& runner);
void RunPerformanceTelemetryTests(kdbg::test::TestRunner& runner);

int main() {
    kdbg::test::TestRunner runner;

    RunPfnAddressTests(runner);
    RunAddressWatchDurabilityTests(runner);
    RunPageTableTests(runner);
    RunPageSessionTests(runner);
    RunProcessMemorySessionTests(runner);
    RunPersistenceMigrationTests(runner);
    RunScannerTests(runner);
    RunAdvancedCoreTests(runner);
    RunKDbgAbiLayoutTests(runner);
    RunKernelModuleTests(runner);
    RunPerformanceTelemetryTests(runner);

    std::cout << "Checks: " << runner.Checks()
              << ", failures: " << runner.Failures() << '\n';
    return runner.Failures() == 0 ? 0 : 1;
}
