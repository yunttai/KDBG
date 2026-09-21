#include "TestHarness.h"

#include "core/kernel/KernelModule.h"
#include "core/kernel/LocalSymbolResolver.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace {

template <typename T>
void Store(std::vector<std::uint8_t>& bytes, std::size_t offset, T value) {
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

std::vector<std::uint8_t> ValidPe64() {
    std::vector<std::uint8_t> bytes(0x200, 0);
    Store<std::uint16_t>(bytes, 0, 0x5A4D);
    Store<std::uint32_t>(bytes, 0x3C, 0x80);
    Store<std::uint32_t>(bytes, 0x80, 0x00004550);
    const std::size_t coff = 0x84;
    Store<std::uint16_t>(bytes, coff, 0x8664);
    Store<std::uint16_t>(bytes, coff + 2, 5);
    Store<std::uint32_t>(bytes, coff + 4, 0x65ABCDEF);
    Store<std::uint16_t>(bytes, coff + 16, 0xF0);
    const std::size_t optional = coff + 20;
    Store<std::uint16_t>(bytes, optional, 0x020B);
    Store<std::uint32_t>(bytes, optional + 56, 0x123000);
    Store<std::uint32_t>(bytes, optional + 64, 0x89ABCDEF);
    return bytes;
}

}  // namespace

void RunKernelModuleTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    KDBG_CHECK(runner, IsCanonicalX64Address(0));
    KDBG_CHECK(runner, IsCanonicalX64Address(0x00007FFFFFFFFFFFULL));
    KDBG_CHECK(runner, IsCanonicalX64Address(0xFFFF800000000000ULL));
    KDBG_CHECK(runner, IsCanonicalX64KernelAddress(0xFFFFF80000000000ULL));
    KDBG_CHECK(runner, !IsCanonicalX64KernelAddress(0x00007FFFFFFFFFFFULL));
    KDBG_CHECK(runner, !IsCanonicalX64Address(0x0000800000000000ULL));
    KDBG_CHECK(runner, !IsCanonicalX64Address(0xFFFF7FFFFFFFFFFFULL));
    KDBG_CHECK(runner, !IsCanonicalX64Address(0x00FF000000000000ULL));
    KDBG_CHECK(runner, IsCanonicalX64Address(0x00FF000000000000ULL, true));
    KDBG_CHECK(runner, IsCanonicalX64KernelAddress(0xFF00000000000000ULL, true));
    KDBG_CHECK(runner, !IsCanonicalX64Address(0x0100000000000000ULL, true));
    KDBG_CHECK(runner, !IsCanonicalX64KernelAddress(0x00FFFFFFFFFFFFFFULL, true));

    KernelModule module;
    module.base = 0xFFFFF80000000000ULL;
    module.image_size = 0x2000;
    KDBG_CHECK(runner, module.Contains(module.base));
    KDBG_CHECK(runner, module.Contains(module.base + 0x1FFF));
    KDBG_CHECK(runner, !module.Contains(module.base - 1));
    KDBG_CHECK(runner, !module.Contains(module.base + 0x2000));
    module.image_size = 0;
    KDBG_CHECK(runner, !module.Contains(module.base));

    auto bytes = ValidPe64();
    const auto parsed = ParsePe64ImageMetadata(bytes);
    KDBG_CHECK(runner, parsed.Ok());
    if (parsed) {
        KDBG_CHECK(runner, parsed.Value().machine == 0x8664);
        KDBG_CHECK(runner, parsed.Value().section_count == 5);
        KDBG_CHECK(runner, parsed.Value().timestamp == 0x65ABCDEF);
        KDBG_CHECK(runner, parsed.Value().image_size == 0x123000);
        KDBG_CHECK(runner, parsed.Value().checksum == 0x89ABCDEF);
    }

    bytes[0] = 0;
    KDBG_CHECK(runner, !ParsePe64ImageMetadata(bytes).Ok());
    bytes = ValidPe64();
    Store<std::uint32_t>(bytes, 0x3C, 0xFFFFFFF0U);
    KDBG_CHECK(runner, !ParsePe64ImageMetadata(bytes).Ok());
    bytes = ValidPe64();
    Store<std::uint16_t>(bytes, 0x84, 0x014C);
    const auto x86 = ParsePe64ImageMetadata(bytes);
    KDBG_CHECK(runner, !x86.Ok());
    if (!x86) KDBG_CHECK(runner, x86.GetError().code == ErrorCode::Unsupported);
    bytes = ValidPe64();
    Store<std::uint16_t>(bytes, 0x86, 97);
    KDBG_CHECK(runner, !ParsePe64ImageMetadata(bytes).Ok());
    bytes = ValidPe64();
    Store<std::uint16_t>(bytes, 0x94, 4);
    KDBG_CHECK(runner, !ParsePe64ImageMetadata(bytes).Ok());
    bytes = ValidPe64();
    Store<std::uint32_t>(bytes, 0x84 + 20 + 56, 0);
    KDBG_CHECK(runner, !ParsePe64ImageMetadata(bytes).Ok());

    const auto local = ParseLocalSymbolPath("C:\\symbols;D:\\private\\ntkrnlmp.pdb");
    KDBG_CHECK(runner, local.Ok());
    if (local) KDBG_CHECK(runner, local.Value().size() == 2);
    KDBG_CHECK(runner, !ParseLocalSymbolPath("").Ok());
    KDBG_CHECK(runner, !ParseLocalSymbolPath("C:\\symbols;").Ok());
    KDBG_CHECK(runner, !ParseLocalSymbolPath("srv*C:\\cache*https://symbols").Ok());
    KDBG_CHECK(runner, !ParseLocalSymbolPath("https://symbols.example").Ok());

    LocalSymbolResolver resolver;
    const auto unresolved_name = resolver.ResolveName("nt!KeBugCheckEx");
    KDBG_CHECK(runner, !unresolved_name.Ok());
    if (!unresolved_name) {
        KDBG_CHECK(runner,
            unresolved_name.GetError().code == ErrorCode::BackendDisconnected);
    }
    const auto unresolved_proof = resolver.ProofForAddress(
        0xFFFFF80000001000ULL);
    KDBG_CHECK(runner, !unresolved_proof.Ok());
    if (!unresolved_proof) {
        KDBG_CHECK(runner,
            unresolved_proof.GetError().code ==
                ErrorCode::BackendDisconnected);
    }

    LocalSymbolModuleProof proof{};
    proof.module_base = 0xFFFFF80000000000ULL;
    proof.module_size = 0x2000U;
#ifdef _WIN32
    proof.loaded_pdb_path = "C:\\symbols\\ntkrnlmp.pdb";
#else
    proof.loaded_pdb_path = "/symbols/ntkrnlmp.pdb";
#endif
    proof.loaded_pdb_basename = proof.loaded_pdb_path.filename().string();
    proof.loaded_pdb_sha256 = std::string(64U, 'a');
    KDBG_CHECK(runner, proof.Contains(proof.module_base));
    KDBG_CHECK(runner, proof.Contains(proof.module_base + 0x1FFFU));
    KDBG_CHECK(runner, !proof.Contains(proof.module_base + 0x2000U));
    KDBG_CHECK(runner, proof.loaded_pdb_basename == "ntkrnlmp.pdb");
    KDBG_CHECK(runner, proof.loaded_pdb_sha256.size() == 64U);

    std::atomic_bool cancel_requested{true};
    std::atomic_size_t completed{99};
    std::atomic_size_t total{0};
    KernelModule pending;
    pending.name = "ntoskrnl.exe";
    const auto cancelled = resolver.Configure(
        "C:\\symbols",
        {pending},
        LocalSymbolLoadControl{
            &cancel_requested, &completed, &total});
    KDBG_CHECK(runner, !cancelled.Ok());
    if (!cancelled) {
        KDBG_CHECK(runner, cancelled.GetError().code == ErrorCode::Cancelled);
    }
    KDBG_CHECK(runner, completed.load() == 0);
    KDBG_CHECK(runner, total.load() == 1);
}
