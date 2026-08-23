#pragma once

#include "core/memory/MemoryAccess.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kdbg {

struct AddressPointerPath {
    MemorySpace space;
    std::uint64_t base_address{0};
    std::vector<std::int64_t> offsets;
    std::uint32_t pointer_size{8};
};

class PointerResolver {
public:
    static constexpr std::size_t kMaxDepth = 32;

    explicit PointerResolver(IMemoryBackend& backend) : backend_(backend) {}

    Result<std::uint64_t> Resolve(const AddressPointerPath& path);

private:
    IMemoryBackend& backend_;
};

}  // namespace kdbg
