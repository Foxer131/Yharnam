#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "Utils.h"
#include "Colors.h"

bool Utils::saveToFile(
    const std::vector<std::pair<std::string, std::string>>& to_save,
    const std::string& file_path) {
    if (to_save.empty() || file_path.empty()) 
        return true;
        
    std::ofstream output_file(file_path);
    if (!output_file.is_open()) {
        std::cerr << Colors::COLOR_RED << "  [-] Failed to open/create file" << Colors::COLOR_RESET;
        return false;
    }

    for (const auto& [username, hash] : to_save) {
        output_file << username << ":" << hash << std::endl;
    }
    output_file.close();
    std::cout << Colors::COLOR_GREEN << "  [*] Wrote to output to " << file_path << Colors::COLOR_RESET << std::endl; 
    return true;
}