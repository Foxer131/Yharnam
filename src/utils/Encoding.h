#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Encoding {

/// @brief Tests whether a byte range contains only printable ASCII characters.
bool isPrintable(const char* data, std::size_t len);

/// @brief Standard Base64 encoding (no line wrapping).
std::string base64Encode(const char* data, std::size_t len);

/// @brief Decodes a standard Base64 string. Stops at the first invalid
///        character (including padding), mirroring a lenient decoder.
std::vector<std::uint8_t> base64Decode(const std::string& input);

}  // namespace Encoding
