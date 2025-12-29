#include "AclService.h"
#include <iostream>
#include <cstring>
#include <sstream>

extern "C" {
    #include <talloc.h>
    #include <samba-4.0/gen_ndr/security.h> 
    #include <samba-4.0/ndr.h>
    
    enum ndr_err_code ndr_pull_security_descriptor(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor *r);

    #ifndef NDR_ERR_CODE_IS_SUCCESS
    #define NDR_ERR_CODE_IS_SUCCESS(x) ((x) == NDR_ERR_SUCCESS)
    #endif
}

struct TallocDeleter {
    void operator()(TALLOC_CTX* ctx) const {
        if (ctx) talloc_free(ctx);
    }
};

using TallocPtr = std::unique_ptr<TALLOC_CTX, TallocDeleter>;

std::vector<Security::Ace> AclService::parseDacl(const std::string& rawOrBase64Data) {
    if (rawOrBase64Data.empty()) {
        return std::vector<Security::Ace>();
    }

    std::vector<uint8_t> blobData = decodeSecurityDescriptorData(rawOrBase64Data);
    if (blobData.empty()) {
        return std::vector<Security::Ace>();
    }

    return parseSecurityDescriptor(blobData);
}

std::vector<std::string> AclService::mapRightsToStrings(uint32_t mask) {
    std::vector<std::string> rights;
    
    addBasicRights(mask, rights);
    addWriteRelatedRights(mask, rights);
    addChildManagementRights(mask, rights);
    addFullControlIfApplicable(mask, rights);
    
    return rights;
}

std::vector<uint8_t> AclService::decodeData(const std::string& input) {
    if (input.substr(0, 2) != "::") {
        return std::vector<uint8_t>(input.begin(), input.end());
    }
    
    return decodeBase64(input.substr(2));
}

std::string AclService::sidToString(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) {
        return "";
    }
    
    int revision = bytes[0];
    int numAuths = bytes[1];
    
    uint64_t authority = 0;
    for (size_t i{}; i < 6; i++) {
        authority = (authority << 8) | bytes[2 + i];
    }
    
    std::stringstream ss;
    ss << "S-" << revision << "-" << authority;
    
    for (size_t i{}; i < numAuths; i++) {
        int offset = 8 + (i * 4);
        if (offset + 4 > bytes.size()) {
            break;
        }
        
        uint32_t subAuth = 0;
        subAuth |= static_cast<uint32_t>(bytes[offset + 0]);
        subAuth |= static_cast<uint32_t>(bytes[offset + 1]) << 8;
        subAuth |= static_cast<uint32_t>(bytes[offset + 2]) << 16;
        subAuth |= static_cast<uint32_t>(bytes[offset + 3]) << 24;
        
        ss << "-" << subAuth;
    }
    
    return ss.str();
}

inline std::vector<uint8_t> AclService::decodeSecurityDescriptorData(
    const std::string& rawOrBase64Data
) {
    return decodeData(rawOrBase64Data);
}

std::vector<Security::Ace> AclService::parseSecurityDescriptor(
    const std::vector<uint8_t>& blobData
) {
    TallocPtr mem_ctx(talloc_new(NULL));
    if (!mem_ctx) {
        return std::vector<Security::Ace>();
    }

    DATA_BLOB blob;
    blob.data = const_cast<uint8_t*>(blobData.data());
    blob.length = blobData.size();

    struct security_descriptor* sd = talloc_zero(mem_ctx.get(), struct security_descriptor);
    
    enum ndr_err_code ndr_err = ndr_pull_struct_blob(
        &blob, 
        mem_ctx.get(), 
        sd, 
        (ndr_pull_flags_fn_t)ndr_pull_security_descriptor
    );

    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err) || !sd->dacl) {
        return std::vector<Security::Ace>();
    }

    return extractAcesFromDacl(sd);
}

std::vector<Security::Ace> AclService::extractAcesFromDacl(struct security_descriptor* sd) {
    std::vector<Security::Ace> resultAces;
    
    for (uint32_t i = 0; i < sd->dacl->num_aces; i++) {
        struct security_ace* sambaAce = &sd->dacl->aces[i];
        
        if (!isAllowedAceType(sambaAce->type)) {
            continue;
        }

        Security::Ace ace = createAceFromSambaAce(sambaAce);
        resultAces.push_back(ace);
    }
    
    return resultAces;
}

inline Security::Ace AclService::createAceFromSambaAce(struct security_ace* sambaAce) {
    Security::Ace ace;
    ace.trusteeSid = sambaSidToString(&sambaAce->trustee);
    ace.rawAccessMask = sambaAce->access_mask;
    ace.isAllow = true;
    ace.isInherited = (sambaAce->flags & SEC_ACE_FLAG_INHERITED_ACE);
    
    return ace;
}

inline bool AclService::isAllowedAceType(uint8_t aceType) const {
    return (aceType == SEC_ACE_TYPE_ACCESS_ALLOWED || 
            aceType == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT);
}

std::string AclService::sambaSidToString(const struct dom_sid* sid) {
    if (!sid) {
        return "";
    }
    
    std::stringstream ss;
    ss << "S-" << static_cast<int>(sid->sid_rev_num);
    
    uint64_t authority = 0;
    for (size_t i{}; i < 6; i++) {
        authority = (authority << 8) | sid->id_auth[i];
    }
    ss << "-" << authority;

    for (size_t i{}; i < sid->num_auths; i++) {
        ss << "-" << sid->sub_auths[i];
    }
    
    return ss.str();
}

std::vector<uint8_t> AclService::decodeBase64(const std::string& base64Input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::vector<int> decodingTable(256, -1);
    for (size_t i = 0; i < 64; i++) {
        decodingTable[static_cast<unsigned char>(base64_chars[i])] = i;
    }
    
    std::string decoded;
    int val = 0;
    int valb = -8;
    
    for (unsigned char c : base64Input) {
        if (decodingTable[c] == -1) {
            break;
        }

        val = (val << 6) + decodingTable[c];
        valb += 6;
        
        if (valb >= 0) {
            decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

void AclService::addBasicRights(uint32_t mask, std::vector<std::string>& rights) {
    using namespace Security;
    
    if (mask & static_cast<uint32_t>(AccessRight::GenericAll)) {
        rights.push_back("GenericAll");
    }
    if (mask & static_cast<uint32_t>(AccessRight::WriteDac)) {
        rights.push_back("WriteDacl");
    }
    if (mask & static_cast<uint32_t>(AccessRight::WriteOwner)) {
        rights.push_back("WriteOwner");
    }
    if (mask & static_cast<uint32_t>(AccessRight::ControlAccess)) {
        rights.push_back("ExtendedRight");
    }
}

void AclService::addWriteRelatedRights(uint32_t mask, std::vector<std::string>& rights) {
    using namespace Security;
    
    bool isWriteProp = (mask & static_cast<uint32_t>(AccessRight::WriteProp));
    bool isValidated = (mask & static_cast<uint32_t>(AccessRight::Self));
    bool isGenericWrite = (mask & static_cast<uint32_t>(AccessRight::GenericWrite));

    if (isGenericWrite || (isWriteProp && isValidated)) {
        rights.push_back("GenericWrite");
    } 
    else if (isWriteProp) {
        rights.push_back("WriteProperty");
    }
    else if (isValidated) {
        rights.push_back("ValidatedWrite");
    }
}

void AclService::addChildManagementRights(uint32_t mask, std::vector<std::string>& rights) {
    using namespace Security;
    
    if (mask & static_cast<uint32_t>(AccessRight::CreateChild)) {
        rights.push_back("CreateChild");
    }
    if (mask & static_cast<uint32_t>(AccessRight::DeleteChild)) {
        rights.push_back("DeleteChild");
    }
}

void AclService::addFullControlIfApplicable(uint32_t mask, std::vector<std::string>& rights) {
    constexpr uint32_t FULL_CONTROL_MASK = 0x000F003F;
    
    if ((mask & FULL_CONTROL_MASK) == FULL_CONTROL_MASK) {
        bool alreadyHasGenericAll = std::find(
            rights.begin(), 
            rights.end(), 
            "GenericAll"
        ) != rights.end();
        
        if (!alreadyHasGenericAll) {
            rights.push_back("FullControl");
        }
    }
}