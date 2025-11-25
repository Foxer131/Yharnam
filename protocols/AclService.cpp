#include "AclService.h"
#include "../utils/Colors.h"
#include <sstream>
#include <iostream>
#include <cstring>
extern "C" {
    #include <talloc.h>
    #include <samba-4.0/gen_ndr/security.h> 
    #include <samba-4.0/ndr.h>
    enum ndr_err_code ndr_pull_security_descriptor(
        struct ndr_pull *ndr, 
        int ndr_flags, 
        struct security_descriptor *r
    );
}

struct TallocDeleter {
    void operator()(TALLOC_CTX* ctx) const {
        if (ctx) {
            talloc_free(ctx);
        }
    }
};

using TallocPtr = std::unique_ptr<TALLOC_CTX, TallocDeleter>;

// Definições de Máscaras
#define PERM_GENERIC_ALL        0x10000000 // Full Control
#define PERM_GENERIC_EXECUTE    0x20000000
#define PERM_GENERIC_WRITE      0x40000000
#define PERM_GENERIC_READ       0x80000000

// Standard Rights
#define PERM_DELETE             0x00010000
#define PERM_READ_CONTROL       0x00020000
#define PERM_WRITE_DAC          0x00040000 // Modify Permissions
#define PERM_WRITE_OWNER        0x00080000 // Take Ownership

// Directory Service Specific Rights (Object Access)
#define PERM_DS_CREATE_CHILD    0x00000001
#define PERM_DS_DELETE_CHILD    0x00000002
#define PERM_DS_LIST_CHILDREN   0x00000004
#define PERM_DS_SELF            0x00000008 // Validated Write
#define PERM_DS_READ_PROP       0x00000010
#define PERM_DS_WRITE_PROP      0x00000020
#define PERM_DS_DELETE_TREE     0x00000040
#define PERM_DS_LIST_OBJECT     0x00000080
#define PERM_DS_CONTROL_ACCESS  0x00000100

static std::string sambaSidToString(const struct dom_sid* sid) {
    if (!sid) return "(null)";
    std::stringstream ss;
    ss << "S-" << (int)sid->sid_rev_num;
    
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) authority = (authority << 8) | sid->id_auth[i];
    ss << "-" << authority;

    for (int i = 0; i < sid->num_auths; i++) ss << "-" << sid->sub_auths[i];
    return ss.str();
}


std::vector<AceInfo> AclService::parseDacl(const std::string& ldapRawValue) {
    std::vector<AceInfo> result;
    
    if (ldapRawValue.empty()) return result;

    std::vector<unsigned char> decodedBytes;
    if (ldapRawValue.substr(0, 2) == "::") {
        decodedBytes = base64Decode(ldapRawValue.substr(2));
    } else {
        decodedBytes.assign(ldapRawValue.begin(), ldapRawValue.end());
    }

    TallocPtr mem_ctx(talloc_new(NULL));
    if (!mem_ctx) return result;

    DATA_BLOB blob;
    blob.data = decodedBytes.data();
    blob.length = decodedBytes.size();

    struct security_descriptor* sd = talloc_zero(mem_ctx.get(), struct security_descriptor);
    
    enum ndr_err_code ndr_err = ndr_pull_struct_blob(&blob, mem_ctx.get(), sd, 
        (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

    if (NDR_ERR_CODE_IS_SUCCESS(ndr_err) && sd->dacl) {
        for (uint32_t i = 0; i < sd->dacl->num_aces; i++) {
            struct security_ace* ace = &sd->dacl->aces[i];

            if (ace->type != SEC_ACE_TYPE_ACCESS_ALLOWED && 
                ace->type != SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT) {
                continue;
            }

            std::string perms = interpretAccessMask(ace->access_mask);
            
            if (!perms.empty()) {
                AceInfo info;
                info.trusteeSid = sambaSidToString(&ace->trustee);
                info.accessMask = ace->access_mask;
                info.humanReadablePermissions = perms;
                info.isAllow = true;
                
                result.push_back(info);
            }
        }
    } else {
        std::cerr << "[-] Failed to unmarshall security descriptor via NDR." << std::endl;
    }

    return result; 
}

std::string AclService::interpretAccessMask(uint32_t mask) {
    std::string ret;
    bool first = true;
    
    auto add = [&](const char* color, const char* text) {
        if (!first) ret += ", ";
        ret += std::string(color) + text + Colors::COLOR_RESET;
        first = false;
    };

    if (mask & PERM_GENERIC_ALL)     add(Colors::COLOR_RED, "GenericAll");
    if (mask & PERM_WRITE_DAC)       add(Colors::COLOR_RED, "WriteDacl");
    if (mask & PERM_WRITE_OWNER)     add(Colors::COLOR_RED, "WriteOwner");
    
    if (mask & PERM_DS_CONTROL_ACCESS) add(Colors::COLOR_RED, "ExtendedRight");

    bool isWriteProp = (mask & PERM_DS_WRITE_PROP);
    bool isValidated = (mask & PERM_DS_SELF);
    
    if ((mask & PERM_GENERIC_WRITE) || (isWriteProp && isValidated)) {
        add(Colors::COLOR_YELLOW, "GenericWrite");
    } 
    else if (isWriteProp) {
        add(Colors::COLOR_YELLOW, "WriteProperty"); 
    }
    else if (isValidated) {
        add(Colors::COLOR_YELLOW, "ValidatedWrite");
    }

    if (mask & PERM_DS_CREATE_CHILD) add(Colors::COLOR_YELLOW, "CreateChild");
    if (mask & PERM_DS_DELETE_CHILD) add(Colors::COLOR_YELLOW, "DeleteChild");

    if ((mask & 0x000F003F) == 0x000F003F && ret.find("GenericAll") == std::string::npos) {
        add(Colors::COLOR_RED, "FullControl");
    }

    return ret;
}

std::vector<unsigned char> AclService::base64Decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return std::vector<unsigned char>(out.begin(), out.end());
}

std::string AclService::sidToString(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) return "";
    
    int revision = bytes[0];
    int numAuths = bytes[1];
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) authority = (authority << 8) | bytes[2+i];
    
    std::stringstream ss;
    ss << "S-" << revision << "-" << authority;
    for (int i = 0; i < numAuths; i++) {
        if (8 + (i * 4) + 4 > bytes.size()) break;
        uint32_t subAuth = 0;
        int offset = 8 + (i * 4);
        subAuth |= (uint32_t)bytes[offset + 0];
        subAuth |= (uint32_t)bytes[offset + 1] << 8;
        subAuth |= (uint32_t)bytes[offset + 2] << 16;
        subAuth |= (uint32_t)bytes[offset + 3] << 24;
        ss << "-" << subAuth;
    }
    return ss.str();
}