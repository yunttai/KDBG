#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"

#include <vector>

namespace kdbg {

class ProcessCatalog {
public:
    static Result<std::vector<ProcessInfo>> Enumerate();
};

}  // namespace kdbg
