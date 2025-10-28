#pragma once
#include <vector>
#include <string>

class Utils {
    public:
        Utils();
    
        static bool saveToFile(const std::vector<std::pair<std::string, std::string>>& to_save, const std::string& file_path);
};