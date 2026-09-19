#include "TestHarness.h"

#include "app/ui/Localization.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] bool IsPrintfConversion(char value) noexcept {
    constexpr std::string_view conversions = "diouxXfFeEgGaAcspnCS";
    return conversions.find(value) != std::string_view::npos;
}

struct PrintfScan {
    std::vector<std::string_view> signatures;
    bool contains_percent_n{false};
};

[[nodiscard]] PrintfScan ScanPrintf(std::string_view text) {
    PrintfScan scan;
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] != '%') {
            continue;
        }
        if (index + 1U < text.size() && text[index + 1U] == '%') {
            ++index;
            continue;
        }

        const auto start = index;
        for (++index; index < text.size(); ++index) {
            if (!IsPrintfConversion(text[index])) {
                continue;
            }
            scan.contains_percent_n = scan.contains_percent_n ||
                text[index] == 'n';
            scan.signatures.push_back(
                text.substr(start, index - start + 1U));
            break;
        }
    }
    return scan;
}

}  // namespace

void RunLocalizationTests(kdbg::test::TestRunner& runner) {
    using namespace std::literals;
    using kdbg::ui::CurrentUiLanguage;
    using kdbg::ui::KoreanFontAvailable;
    using kdbg::ui::ParseUiLanguage;
    using kdbg::ui::SetKoreanFontAvailable;
    using kdbg::ui::SetUiLanguage;
    using kdbg::ui::UiLabel;
    using kdbg::ui::UiLanguage;
    using kdbg::ui::UiLanguageCode;
    using kdbg::ui::UiText;
    using kdbg::ui::UiTranslationCatalog;

    SetKoreanFontAvailable(false);
    KDBG_CHECK(runner, !KoreanFontAvailable());
    KDBG_CHECK(runner, CurrentUiLanguage() == UiLanguage::English);
    KDBG_CHECK(runner, !SetUiLanguage(UiLanguage::Korean));
    KDBG_CHECK(runner, CurrentUiLanguage() == UiLanguage::English);

    KDBG_CHECK(runner, std::string_view{UiLanguageCode(UiLanguage::English)} ==
        "en-US");
    KDBG_CHECK(runner, std::string_view{UiLanguageCode(UiLanguage::Korean)} ==
        "ko-KR");
    KDBG_CHECK(runner, ParseUiLanguage("en") == UiLanguage::English);
    KDBG_CHECK(runner, ParseUiLanguage("EN-US") == UiLanguage::English);
    KDBG_CHECK(runner, ParseUiLanguage("English") == UiLanguage::English);
    KDBG_CHECK(runner, ParseUiLanguage("ko") == UiLanguage::Korean);
    KDBG_CHECK(runner, ParseUiLanguage("KO-kr") == UiLanguage::Korean);
    KDBG_CHECK(runner, ParseUiLanguage("한국어") == UiLanguage::Korean);
    KDBG_CHECK(runner, !ParseUiLanguage("de-DE").has_value());
    KDBG_CHECK(runner, !ParseUiLanguage("").has_value());

    KDBG_CHECK(runner, std::string_view{UiText("Refresh")} == "Refresh");
    KDBG_CHECK(runner, UiLabel("Refresh", "toolbar.refresh") ==
        "Refresh###toolbar.refresh");

    SetKoreanFontAvailable(true);
    KDBG_CHECK(runner, KoreanFontAvailable());
    KDBG_CHECK(runner, SetUiLanguage(UiLanguage::Korean));
    KDBG_CHECK(runner, CurrentUiLanguage() == UiLanguage::Korean);
    KDBG_CHECK(runner, std::string_view{UiText("Refresh")} == "새로고침");
    KDBG_CHECK(runner, UiLabel("Refresh", "toolbar.refresh") ==
        "새로고침###toolbar.refresh");
    constexpr std::array expected_tab_labels{
        std::pair{"Driver"sv, "드라이버"sv},
        std::pair{"Physical Memory"sv, "물리 메모리"sv},
        std::pair{"Memory Map"sv, "메모리 맵"sv},
        std::pair{"Process Memory"sv, "프로세스 메모리"sv},
        std::pair{"Process Scanner"sv, "프로세스 메모리 스캐너"sv},
        std::pair{"Pointer Scanner"sv, "포인터 스캐너"sv},
        std::pair{"Kernel Explorer"sv, "커널 탐색기"sv},
        std::pair{"Page Tables"sv, "페이지 테이블"sv},
        std::pair{"PFN Ownership"sv, "PFN 소유권"sv},
    };
    for (const auto& [english, korean] : expected_tab_labels) {
        KDBG_CHECK(runner, std::string_view{UiText(english)} == korean);
    }
    KDBG_CHECK(runner, std::string_view{UiText("PFN")} == "PFN");
    KDBG_CHECK(runner,
        std::string_view{UiText("Uncatalogued technical diagnostic")} ==
            "Uncatalogued technical diagnostic");

    const std::string korean_text{UiText("No local changes.")};
    KDBG_CHECK(runner, korean_text == "로컬 변경 없음.");
    KDBG_CHECK(runner, !korean_text.empty());
    if (!korean_text.empty()) {
        KDBG_CHECK(runner,
            static_cast<unsigned char>(korean_text.front()) >= 0x80U);
    }

    const auto catalog = UiTranslationCatalog();
    KDBG_CHECK(runner, catalog.size() >= 100U);
    std::unordered_set<std::string_view> english_keys;
    bool catalog_valid = true;
    bool printf_signatures_match = true;
    bool catalog_forbids_percent_n = true;
    for (const auto& entry : catalog) {
        catalog_valid = catalog_valid && !entry.english.empty() &&
            !entry.korean.empty() && english_keys.insert(entry.english).second;
        const auto english_printf = ScanPrintf(entry.english);
        const auto korean_printf = ScanPrintf(entry.korean);
        printf_signatures_match = printf_signatures_match &&
            english_printf.signatures == korean_printf.signatures;
        catalog_forbids_percent_n = catalog_forbids_percent_n &&
            !english_printf.contains_percent_n &&
            !korean_printf.contains_percent_n;
    }
    KDBG_CHECK(runner, catalog_valid);
    KDBG_CHECK(runner, printf_signatures_match);
    KDBG_CHECK(runner, catalog_forbids_percent_n);
    KDBG_CHECK(runner,
        std::ranges::any_of(catalog, [](const auto& entry) {
            return entry.english == "Apply Changed Runs & Verify" &&
                entry.korean.find("Verify") == std::string_view::npos;
        }));

    // Losing the Korean font immediately restores a renderable language.
    SetKoreanFontAvailable(false);
    KDBG_CHECK(runner, CurrentUiLanguage() == UiLanguage::English);
    KDBG_CHECK(runner, std::string_view{UiText("Refresh")} == "Refresh");
}
