#pragma once
#include <string>
#include <utility>
#include <vector>

namespace Utils {

/// @brief Writes "name:value" pairs (one per line) to @p filePath.
/// @return true on success, or when there is nothing to write; false on I/O error.
bool saveToFile(const std::vector<std::pair<std::string, std::string>>& entries,
                const std::string& filePath);

}  // namespace Utils
