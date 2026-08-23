#pragma once

#include <cstdint>
#include <string>

namespace kdbg {

struct BackendInfo {
    std::string name;
    std::uint32_t abi_version{0};
    bool connected{false};
    bool write_enabled{false};
    bool is_mock{false};
    bool supports_process_context{false};
    bool supports_fixture{false};
    bool supports_la57{false};
};

}  // namespace kdbg
