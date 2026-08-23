#include "app/disasm/ZydisDisassembler.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstdio>

namespace kdbg {

Result<std::vector<DisassembledInstruction>> ZydisDisassembler::Decode(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint32_t byte_count,
    std::size_t max_instructions) const {
    if (address == 0 || byte_count == 0 || max_instructions == 0) {
        return Result<std::vector<DisassembledInstruction>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid disassembly range",
            "ZydisDisassembler::Decode"));
    }
    const auto bytes_result = memory.Read(address, byte_count);
    if (!bytes_result) {
        return Result<std::vector<DisassembledInstruction>>::Failure(bytes_result.GetError());
    }

    ZydisDecoder decoder{};
    const auto mode = memory.PointerSize() == 4
        ? ZYDIS_MACHINE_MODE_LEGACY_32
        : ZYDIS_MACHINE_MODE_LONG_64;
    const auto stack_width = memory.PointerSize() == 4
        ? ZYDIS_STACK_WIDTH_32
        : ZYDIS_STACK_WIDTH_64;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stack_width))) {
        return Result<std::vector<DisassembledInstruction>>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Zydis decoder initialization failed",
            "ZydisDisassembler::Decode"));
    }
    ZydisFormatter formatter{};
    if (!ZYAN_SUCCESS(ZydisFormatterInit(
            &formatter,
            ZYDIS_FORMATTER_STYLE_INTEL))) {
        return Result<std::vector<DisassembledInstruction>>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Zydis formatter initialization failed",
            "ZydisDisassembler::Decode"));
    }

    const auto& data = bytes_result.Value();
    std::vector<DisassembledInstruction> output;
    output.reserve(std::min<std::size_t>(max_instructions, 256));
    std::size_t offset = 0;
    while (offset < data.size() && output.size() < max_instructions) {
        ZydisDecodedInstruction instruction{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder,
            data.data() + offset,
            data.size() - offset,
            &instruction,
            operands.data());
        if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
            DisassembledInstruction invalid{};
            invalid.address = address + offset;
            invalid.bytes.push_back(data[offset]);
            char buffer[32]{};
            std::snprintf(buffer, sizeof(buffer), "db 0x%02X", data[offset]);
            invalid.text = buffer;
            output.push_back(std::move(invalid));
            ++offset;
            continue;
        }

        std::array<char, 256> formatted{};
        const auto format_status = ZydisFormatterFormatInstruction(
            &formatter,
            &instruction,
            operands.data(),
            instruction.operand_count_visible,
            formatted.data(),
            formatted.size(),
            address + offset,
            nullptr);

        DisassembledInstruction decoded{};
        decoded.address = address + offset;
        decoded.bytes.assign(
            data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + instruction.length));
        decoded.text = ZYAN_SUCCESS(format_status)
            ? formatted.data()
            : "<format-error>";
        decoded.call = instruction.meta.category == ZYDIS_CATEGORY_CALL;
        decoded.ret = instruction.meta.category == ZYDIS_CATEGORY_RET;
        decoded.branch = decoded.call || decoded.ret ||
            instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
        output.push_back(std::move(decoded));
        offset += instruction.length;
    }
    return Result<std::vector<DisassembledInstruction>>::Success(std::move(output));
}

}  // namespace kdbg
