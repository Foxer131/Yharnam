#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

struct AceInfo {
    std::string trusteeSid;
    uint32_t accessMask;
    std::string humanReadablePermissions;
    bool isAllow;
};

class AclService {
    std::string interpretAccessMask(uint32_t mask);
public:
    AclService() = default;
    ~AclService() = default;

    /**
     * @brief Faz o parsing do nTSecurityDescriptor (binário ou base64)
     * e retorna uma lista de ACEs sanitizadas.
     */
    std::vector<AceInfo> parseDacl(const std::string& ldapRawValue);

    static std::vector<unsigned char> base64Decode(const std::string& input);
    static std::string sidToString(const std::vector<uint8_t>& sidBytes);
};