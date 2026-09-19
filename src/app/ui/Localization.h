#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace kdbg::ui {

enum class UiLanguage {
    English,
    Korean,
};

struct TranslationEntry {
    std::string_view english;
    std::string_view korean;
};

// The catalog is compiled into KDBG.  Runtime language selection never loads
// a language pack or another product binary.
[[nodiscard]] std::span<const TranslationEntry>
UiTranslationCatalog() noexcept;

[[nodiscard]] UiLanguage CurrentUiLanguage() noexcept;

// Korean can be selected only after the application has loaded a font that
// covers the Korean glyph range.  English is always available.
[[nodiscard]] bool SetUiLanguage(UiLanguage language) noexcept;
void SetKoreanFontAvailable(bool available) noexcept;
[[nodiscard]] bool KoreanFontAvailable() noexcept;

[[nodiscard]] const char* UiLanguageCode(UiLanguage language) noexcept;
[[nodiscard]] std::optional<UiLanguage>
ParseUiLanguage(std::string_view language) noexcept;

// Unknown strings deliberately remain English.  This keeps technical terms
// and diagnostics intact instead of presenting an unreliable literal
// translation.  Callers pass null-terminated labels (normally literals).
[[nodiscard]] const char* UiText(std::string_view english) noexcept;

// Keep ImGui identity stable while changing only the visible label.
[[nodiscard]] std::string UiLabel(
    std::string_view english,
    std::string_view stable_id);

}  // namespace kdbg::ui
