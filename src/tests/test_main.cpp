#include "TestHarness.h"

#include <iostream>

void RunPfnAddressTests(kdbg::test::TestRunner& runner);
void RunPageTableTests(kdbg::test::TestRunner& runner);
void RunPageSessionTests(kdbg::test::TestRunner& runner);
void RunProcessMemorySessionTests(kdbg::test::TestRunner& runner);
void RunScannerTests(kdbg::test::TestRunner& runner);
void RunAdvancedCoreTests(kdbg::test::TestRunner& runner);
void RunKDbgAbiLayoutTests(kdbg::test::TestRunner& runner);

int main() {
    kdbg::test::TestRunner runner;

    RunPfnAddressTests(runner);
    RunPageTableTests(runner);
    RunPageSessionTests(runner);
    RunProcessMemorySessionTests(runner);
    RunScannerTests(runner);
    RunAdvancedCoreTests(runner);
    RunKDbgAbiLayoutTests(runner);

    std::cout << "Checks: " << runner.Checks()
              << ", failures: " << runner.Failures() << '\n';
    return runner.Failures() == 0 ? 0 : 1;
}
