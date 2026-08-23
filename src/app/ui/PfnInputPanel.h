#pragma once

#include "core/memory/IMemoryBackend.h"
#include "core/memory/PhysicalPageSession.h"

#include <array>
#include <cstdint>
#include <string>

namespace kdbg {

class PfnInputPanel {
public:
    bool Draw(IMemoryBackend& backend, PhysicalPageSession& session);

    [[nodiscard]] const std::string& Status() const noexcept;
    void SetPfn(std::uint64_t pfn) noexcept;

private:
    std::array<char, 64> input_{'0', 'x', '1', '0', '0', '\0'};
    std::string status_;
};

}  // namespace kdbg
