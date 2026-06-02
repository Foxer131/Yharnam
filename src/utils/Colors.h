#pragma once

// ANSI terminal colour escape codes. Header-only: C++17 `inline` variables
// give every translation unit the same definition with no separate .cpp file.
namespace Colors {
    inline constexpr const char* COLOR_RED    = "\033[91m";
    inline constexpr const char* COLOR_GREEN  = "\033[92m";
    inline constexpr const char* COLOR_BLUE   = "\033[94m";
    inline constexpr const char* COLOR_YELLOW = "\033[93m";
    inline constexpr const char* COLOR_RESET  = "\033[0m";
}
