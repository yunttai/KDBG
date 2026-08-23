#pragma once

#include <cstdint>

namespace kdbg {

// Events are deliberately enumerated so callers cannot accidentally place
// memory bytes, credentials, user-entered paths, or other payloads in the log.
enum class DiagnosticEvent : std::uint32_t {
    ApplicationStarting,
    ApplicationStarted,
    ApplicationStopping,
    ApplicationStopped,
    WindowClassRegistrationFailed,
    WindowCreationFailed,
    GraphicsInitializationFailed,
    FatalStandardException,
    FatalUnknownException,
    DriverConnectSucceeded,
    DriverConnectFailed,
    DriverServiceInstallSucceeded,
    DriverServiceInstallFailed,
    DriverServiceStartSucceeded,
    DriverServiceStartFailed,
    DriverServiceStopSucceeded,
    DriverServiceStopFailed,
    DriverServiceRemoveSucceeded,
    DriverServiceRemoveFailed,
    ProbeServiceInstallSucceeded,
    ProbeServiceInstallFailed,
    ProbeServiceStartSucceeded,
    ProbeServiceStartFailed,
    ProbeServiceStopSucceeded,
    ProbeServiceStopFailed,
    ProbeServiceRemoveSucceeded,
    ProbeServiceRemoveFailed,
    ProbeDeviceOpenSucceeded,
    ProbeDeviceOpenFailed,
    ProbeQuerySucceeded,
    ProbeQueryFailed,
    ProbeResetSucceeded,
    ProbeResetFailed,
    PhysicalGateLockSucceeded,
    PhysicalGateLockFailed,
    PhysicalApplySucceeded,
    PhysicalApplyFailed,
    PhysicalRollbackSucceeded,
    PhysicalRollbackFailed
};

void InitializeLocalDiagnostics() noexcept;
void ShutdownLocalDiagnostics() noexcept;
void LogDiagnostic(
    DiagnosticEvent event,
    std::uint64_t status_code = 0,
    std::uint64_t native_code = 0) noexcept;

}  // namespace kdbg
