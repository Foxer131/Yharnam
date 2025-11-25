#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint> 
#include "Analysis.h" 
#include "../../utils/Colors.h"

extern "C" {
    #include <talloc.h>
    #include <samba-4.0/gen_ndr/security.h> 
    #include <samba-4.0/ndr.h>                  

    ndr_err_code ndr_pull_security_descriptor(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor *r);
    
    #ifndef NDR_ERR_CODE_IS_SUCCESS
    #define NDR_ERR_CODE_IS_SUCCESS(x) ((x) == NDR_ERR_SUCCESS)
    #endif
}

// Definições de Máscaras
#define PERM_GENERIC_ALL        0x10000000
#define PERM_GENERIC_EXECUTE    0x20000000
#define PERM_GENERIC_WRITE      0x40000000
#define PERM_GENERIC_READ       0x80000000
#define PERM_WRITE_DAC          0x00040000
#define PERM_WRITE_OWNER        0x00080000
#define PERM_DS_CREATE_CHILD    0x00000001
#define PERM_DS_DELETE_CHILD    0x00000002
#define PERM_DS_SELF            0x00000008
#define PERM_DS_WRITE_PROP      0x00000020
#define PERM_DS_CONTROL_ACCESS  0x00000100

Analysis::FindAcls::FindAcls(I_LdapQuerier& ldap_, 
                            AclService& acl_, 
                            const std::string& username_,
                            const std::vector<std::string>& customTargets_,
                            bool scanAll_    
                        ) 
    : ldap(ldap_), 
    acl(acl_), 
    myUsername(username_), 
    scanAll(scanAll_) {
        if (!customTargets_.empty()) {
            targets = customTargets_;
            scanAll = false; 
        }
    }

static std::string bytesToSidString(const std::string& rawVal) {
    std::vector<unsigned char> bytes;
    if (rawVal.substr(0, 2) == "::") {
        bytes = AclService::base64Decode(rawVal.substr(2));
    } else {
        bytes.assign(rawVal.begin(), rawVal.end());
    }
    return AclService::sidToString(bytes);
}

std::string Analysis::FindAcls::resolveSid(const std::string& sidStr, const std::string& baseDN) {
    if (sidNameCache.count(sidStr)) return sidNameCache[sidStr];
    if (sidStr == "S-1-5-11") return "Authenticated Users";
    if (sidStr == "S-1-1-0") return "Everyone";
    if (sidStr.find("-512") != std::string::npos && sidStr.length() < 45) return "Domain Admins";
    return sidStr;
}

std::vector<std::string> Analysis::FindAcls::enumerateAllUsers(const std::string& baseDN) {
    std::cout << "    [*] Enumerating all users (may take a while)" << std::endl;
    std::string query = "(&(objectClass=user)(objectCategory=person)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    std::vector<std::string> attrs = {"sAMAccountName"};
    auto results = ldap.executeQuery(baseDN, query, attrs);

    std::vector<std::string> users;
    for (const auto& entry : results) {
        if (entry.count("sAMAccountName")) 
            users.push_back(entry.at("sAMAccountName").front());
    }
    return users;
}

void Analysis::FindAcls::populateMySids(const std::string& baseDN) {
    std::string shortUser = myUsername;
    size_t at = shortUser.find('@');
    if (at != std::string::npos) 
        shortUser = shortUser.substr(0, at);
    
    std::string query = "(sAMAccountName=" + shortUser + ")";
    std::vector<std::string> attrs = {"distinguishedName"};
    auto resDN = ldap.executeQuery(baseDN, query, attrs);
    
    if(resDN.empty()) {
        std::cerr << Colors::COLOR_RED << "[-] Error: Could not find user " << shortUser << ". Filtering disabled." << Colors::COLOR_RESET << std::endl;
        return;
    }
    
    std::string userDN = resDN[0].at("distinguishedName").front();
    
    auto resGroups = ldap.executeBaseQuery(userDN, "(objectClass=*)", {"objectSid", "tokenGroups"});
    if(resGroups.empty()) {
        std::cerr << Colors::COLOR_RED << "[-] Error: Could not retrieve tokenGroups for " << shortUser << Colors::COLOR_RESET << std::endl;
        return;
    }

    const auto& me = resGroups[0];

    if (me.count("objectSid")) {
        std::string sid = bytesToSidString(me.at("objectSid").front());
        mySids.insert(sid);
        sidNameCache[sid] = shortUser;
    }

    if (me.count("tokenGroups")) {
        for (const auto& val : me.at("tokenGroups")) {
            std::string grpSid = bytesToSidString(val);
            mySids.insert(grpSid);
        }
    }
    
    mySids.insert("S-1-1-0"); // Everyone
    mySids.insert("S-1-5-11"); // Auth Users
    sidNameCache["S-1-1-0"] = "Everyone";
    sidNameCache["S-1-5-11"] = "Auth Users";
}

void Analysis::FindAcls::run(const ModuleRuntimeContext& ctx) {
    populateMySids(ctx.baseDN);
    if (scanAll) {
        targets = enumerateAllUsers(ctx.baseDN);
    }
    std::cout << "    [*] Scanning for ACLs on " << targets.size() << " targets" << std::endl;
    
    for (const auto& target : targets) 
        checkTarget(target, ctx.baseDN);
}

void Analysis::FindAcls::checkTarget(const std::string& target, const std::string& baseDN) {
    std::string query = "(sAMAccountName=" + target + ")";
    std::vector<std::string> attrs = {"nTSecurityDescriptor"};
    
    auto results = ldap.executeQuery(baseDN, query, attrs);
    if (results.empty()) {
        // std::cout << "DEBUG: Target " << target << " not found in LDAP." << std::endl;
        return;
    }

    const auto& obj = results[0];
    
    if (!obj.count("nTSecurityDescriptor") || obj.at("nTSecurityDescriptor").empty()) {
        std::cerr << Colors::COLOR_RED << "[-] Warning: Could not read nTSecurityDescriptor for " << target << " (Access Denied or SD Control missing?)" << Colors::COLOR_RESET << std::endl;
        return;
    }

    std::string rawSD = results[0].at("nTSecurityDescriptor").front();

    std::vector<AceInfo> aces = acl.parseDacl(rawSD);
    
    if (aces.empty()) {
        // std::cout << "DEBUG: No ACEs found for " << target << std::endl;
    }

    bool headerPrinted = false;

    for (const auto& ace : aces) {
        if (ace.trusteeSid == "S-1-5-18" || ace.trusteeSid == "S-1-5-10" || ace.trusteeSid == "S-1-3-0") continue;
        
        if (ace.humanReadablePermissions.find("ExtendedRight") != std::string::npos) {
            if (ace.trusteeSid == "S-1-1-0" || ace.trusteeSid == "S-1-5-11") continue;
        }
        if (mySids.empty() || mySids.count(ace.trusteeSid)) {
            if (!headerPrinted) {
                std::cout << "[*] Target: " << Colors::COLOR_BLUE << target << Colors::COLOR_RESET << "\n";
                headerPrinted = true;
            }
            
            std::string name = resolveSid(ace.trusteeSid, baseDN);
            
            std::cout << "    -> " << ace.humanReadablePermissions << " granted to: ";
            if (name != ace.trusteeSid) 
                std::cout << name;
            else 
                std::cout << ace.trusteeSid;
            std::cout << "\n";
        }
    }
}