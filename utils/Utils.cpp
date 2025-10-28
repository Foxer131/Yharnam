#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "Utils.h"


bool Utils::saveToFile(
    const std::vector<std::pair<std::string, std::string>>& to_save,
    const std::string& file_path) {
    if (to_save.empty() || file_path.empty()) 
        return true;
        
    std::ofstream output_file(file_path);
    if (!output_file.is_open()) {
        std::cerr << "  [-] Failed to open/create file";
        return false;
    }

    for (const auto& [username, hash] : to_save) {
        output_file << username << ":" << hash << std::endl;
    }
    output_file.close();
    std::cout << "  [*] Wrote to output to " << file_path << std::endl; 
    return true;
}