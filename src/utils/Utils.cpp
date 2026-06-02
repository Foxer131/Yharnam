#include "Utils.h"

#include <fstream>
#include <iostream>

#include "utils/Colors.h"

namespace Utils {

bool saveToFile(const std::vector<std::pair<std::string, std::string>>& entries,
                const std::string& filePath) {
    if (entries.empty() || filePath.empty()) {
        return true;
    }

    std::ofstream output(filePath);
    if (!output.is_open()) {
        std::cerr << Colors::COLOR_RED << "  [-] Failed to open/create file"
                  << Colors::COLOR_RESET << std::endl;
        return false;
    }

    for (const auto& [name, value] : entries) {
        output << name << ":" << value << '\n';
    }

    std::cout << Colors::COLOR_GREEN << "  [*] Wrote output to " << filePath
              << Colors::COLOR_RESET << std::endl;
    return true;
}

}  // namespace Utils
