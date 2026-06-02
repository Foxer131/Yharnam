#pragma once
#include <string>

namespace StringUtils {

    /**
     * @brief Returns the portion of a UPN-style username before '@'.
     *
     * Ex.: "isabel.l@YHARNAM.LOCAL" -> "isabel.l".
     * If there is no '@', the input is returned unchanged.
     */
    inline std::string shortUsername(const std::string& fullUsername) {
        size_t pos = fullUsername.find('@');
        if (pos != std::string::npos) {
            return fullUsername.substr(0, pos);
        }
        return fullUsername;
    }

}
