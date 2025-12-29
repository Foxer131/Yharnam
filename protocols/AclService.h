#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <algorithm>

struct dom_sid;

namespace Security {
    enum class AccessRight : uint32_t {
        GenericAll      = 0x10000000,
        GenericExecute  = 0x20000000,
        GenericWrite    = 0x40000000,
        GenericRead     = 0x80000000,
        WriteDac        = 0x00040000,
        WriteOwner      = 0x00080000,
        CreateChild     = 0x00000001,
        DeleteChild     = 0x00000002,
        Self            = 0x00000008, 
        WriteProp       = 0x00000020,
        ControlAccess   = 0x00000100,
        DeleteTree      = 0x00000040,
        FullControl     = 0x000F003F
    };
    
    struct Ace {
        std::string trusteeSid;
        uint32_t rawAccessMask;
        bool isAllow;
        bool isInherited;
        
        bool hasRight(AccessRight right) const {
            return (rawAccessMask & static_cast<uint32_t>(right)) == static_cast<uint32_t>(right);
        }
    };
}

class AclService {
public:
    AclService() = default;
    ~AclService() = default;
    
    /**
     * @brief Parses a raw NTSecurityDescriptor (binary or base64 with '::' prefix).
     * @return A vector of clean Security::Ace objects.
     */
    std::vector<Security::Ace> parseDacl(const std::string& rawOrBase64Data);
    
    static std::string sidToString(const std::vector<uint8_t>& sidBytes);
    
    static std::vector<std::string> mapRightsToStrings(uint32_t mask);
    
    static std::vector<uint8_t> decodeData(const std::string& input);

private:
    std::vector<uint8_t> decodeSecurityDescriptorData(const std::string& rawOrBase64Data);
    std::vector<Security::Ace> parseSecurityDescriptor(const std::vector<uint8_t>& blobData);
    std::vector<Security::Ace> extractAcesFromDacl(struct security_descriptor* sd);
    
    Security::Ace createAceFromSambaAce(struct security_ace* sambaAce);
    bool isAllowedAceType(uint8_t aceType) const;
    
    std::string sambaSidToString(const struct dom_sid* sid);
    
    static std::vector<uint8_t> decodeBase64(const std::string& base64Input);
    
    static void addBasicRights(uint32_t mask, std::vector<std::string>& rights);
    static void addWriteRelatedRights(uint32_t mask, std::vector<std::string>& rights);
    static void addChildManagementRights(uint32_t mask, std::vector<std::string>& rights);
    static void addFullControlIfApplicable(uint32_t mask, std::vector<std::string>& rights);
};