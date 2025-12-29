#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <set>
#include <algorithm>
#include "Analysis.h" 
#include "../../utils/Colors.h"

static const char* getPermissionColor(const std::string& perm) {
    if (perm == "GenericAll" || perm == "WriteDacl" || perm == "WriteOwner" || perm == "FullControl") {
        return Colors::COLOR_RED;
    }
    return Colors::COLOR_YELLOW;
}

Analysis::FindAcls::FindAcls(
    LdapQuerier& ldap_, 
    AclService& acl_, 
    const std::string& username_,
    const std::vector<std::string>& customTargets_,
    bool scanAll_
) 
    : ldap(ldap_)
    , acl(acl_)
    , myUsername(username_)
    , scanAll(scanAll_) 
{
    if (!customTargets_.empty()) {
        targets = customTargets_;
        scanAll = false; 
    }
}

void Analysis::FindAcls::run(const ModuleRuntimeContext& ctx) {
    populateMySids(ctx.baseDN);
    
    if (scanAll) {
        targets = enumerateAllUsers(ctx.baseDN);
    }
    
    std::cout << "    [*] Scanning for ACLs on " << targets.size() << " targets" << std::endl;
    
    for (const auto& target : targets) {
        scanTargetAcls(target, ctx.baseDN);
    }
}

std::vector<std::string> Analysis::FindAcls::enumerateAllUsers(const std::string& baseDN) {
    std::cout << "    [*] Enumerating all users (may take a while)" << std::endl;
    
    std::string query = buildUserEnumerationQuery();
    std::vector<std::string> attrs = {"sAMAccountName"};
    
    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attrs);
    
    return extractUserNamesFromResults(results);
}

void Analysis::FindAcls::populateMySids(const std::string& baseDN) {
    std::string shortUsername = extractShortUsername(myUsername);
    std::string userDN = getUserDistinguishedName(shortUsername, baseDN);
    
    if (userDN.empty()) {
        displayUserNotFoundError(shortUsername);
        return;
    }
    
    collectUserSids(userDN);
    addWellKnownSids();
}

void Analysis::FindAcls::scanTargetAcls(const std::string& target, const std::string& baseDN) {
    std::string securityDescriptor = fetchTargetSecurityDescriptor(target, baseDN);
    
    if (securityDescriptor.empty()) {
        return;
    }
    
    std::vector<Security::Ace> aces = acl.parseDacl(securityDescriptor);
    std::vector<AclEntry> relevantAcls = filterRelevantAcls(aces, baseDN);
    
    if (!relevantAcls.empty()) {
        displayTargetAcls(target, relevantAcls);
    }
}

std::string Analysis::FindAcls::fetchTargetSecurityDescriptor(
    const std::string& target,
    const std::string& baseDN
) {
    std::string query = "(sAMAccountName=" + target + ")";
    std::vector<std::string> attrs = {"nTSecurityDescriptor"};
    
    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attrs);
    
    if (results.empty()) {
        return "";
    }
    
    const auto& obj = results[0];
    
    if (!obj.count("nTSecurityDescriptor") || obj.at("nTSecurityDescriptor").empty()) {
        displaySecurityDescriptorError(target);
        return "";
    }
    
    return obj.at("nTSecurityDescriptor").front();
}

std::vector<Analysis::FindAcls::AclEntry> Analysis::FindAcls::filterRelevantAcls(
    const std::vector<Security::Ace>& aces,
    const std::string& baseDN
) {
    std::vector<AclEntry> relevantAcls;
    
    for (const auto& ace : aces) {
        if (shouldSkipAce(ace)) {
            continue;
        }
        
        auto permissions = AclService::mapRightsToStrings(ace.rawAccessMask);
        if (permissions.empty()) {
            continue;
        }
        
        if (isNoisePermission(ace, permissions)) {
            continue;
        }
        
        AclEntry entry;
        entry.trusteeSid = ace.trusteeSid;
        entry.trusteeName = resolveSid(ace.trusteeSid, baseDN);
        entry.permissions = permissions;
        entry.isInherited = ace.isInherited;
        
        relevantAcls.push_back(entry);
    }
    
    return relevantAcls;
}

bool Analysis::FindAcls::shouldSkipAce(const Security::Ace& ace) const {
    if (isSystemAccount(ace.trusteeSid)) {
        return true;
    }
    
    bool isPublicSid = isWellKnownPublicSid(ace.trusteeSid);
    bool belongsToUser = mySids.count(ace.trusteeSid) > 0;
    bool isRelevant = mySids.empty() || belongsToUser || isPublicSid;
    
    return !isRelevant;
}

inline bool Analysis::FindAcls::isSystemAccount(const std::string& sid) const {
    return (sid == "S-1-5-18" ||  // SYSTEM
            sid == "S-1-5-10" ||  // SELF
            sid == "S-1-3-0");    // CREATOR OWNER
}

inline bool Analysis::FindAcls::isWellKnownPublicSid(const std::string& sid) const {
    return (sid == "S-1-1-0" ||   // Everyone
            sid == "S-1-5-11");   // Authenticated Users
}

bool Analysis::FindAcls::isNoisePermission(
    const Security::Ace& ace,
    const std::vector<std::string>& permissions
) const {
    if (isWellKnownPublicSid(ace.trusteeSid) && 
        permissions.size() == 1 && 
        permissions[0] == "ExtendedRight") {
        return true;
    }
    
    return false;
}

std::string Analysis::FindAcls::resolveSid(const std::string& sidStr, const std::string& baseDN) {
    if (sidNameCache.count(sidStr)) {
        return sidNameCache[sidStr];
    }
    
    std::string resolvedName = resolveWellKnownSid(sidStr);
    if (!resolvedName.empty()) {
        sidNameCache[sidStr] = resolvedName;
        return resolvedName;
    }
    
    return resolveNotKnownSid(baseDN, sidStr);
}

inline std::string Analysis::FindAcls::resolveNotKnownSid(
    const std::string& baseDN,
    const std::string& sidStr
) {
    std::string query = "(objectSid=" + sidStr + ")";
    std::vector<std::string> attrs = {"sAMAccountName", "name", "cn"};

    LDAPResult searchResult = ldap.executeQueryAndUnpackData(baseDN, query, attrs);

    if (!searchResult.empty()) {
        auto entry = searchResult[0];
        std::string nameFound;

        if (entry.count("sAMAccountName")) 
            nameFound = entry.at("sAMAccountName").front();
        else if (entry.count("name")) 
            nameFound = entry.at("name").front();
        else if (entry.count("cn")) 
            nameFound = entry.at("cn").front();

        if (!nameFound.empty()) {
            sidNameCache[sidStr] = nameFound;
            return nameFound;
        }
    }
    return sidStr;
}

std::string Analysis::FindAcls::resolveWellKnownSid(const std::string& sidStr) const {
    if (sidStr == "S-1-5-11") 
        return "Authenticated Users";
    if (sidStr == "S-1-1-0") 
        return "Everyone";
    if (sidStr.find("-512") != std::string::npos && sidStr.length() < 45) 
        return "Domain Admins";
    if (sidStr.find("-519") != std::string::npos) 
        return "Enterprise Admins";
    if (sidStr.find("-544") != std::string::npos) 
        return "Administrators";
    
    return "";
}

inline std::string Analysis::FindAcls::buildUserEnumerationQuery() const {
    return 
    "(&"
      "(|"                                     
         "(&(objectClass=user)(objectCategory=person))"  
         "(objectClass=group)"                           
      ")"
      "(!(objectClass=computer))"               
      "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    ")";
}

std::vector<std::string> Analysis::FindAcls::extractUserNamesFromResults(
    const LDAPResult& results
) const {
    std::vector<std::string> users;
    
    for (const auto& entry : results) {
        if (entry.count("sAMAccountName")) {
            users.push_back(entry.at("sAMAccountName").front());
        }
    }
    
    return users;
}

inline std::string Analysis::FindAcls::extractShortUsername(const std::string& fullUsername) const {
    size_t atPos = fullUsername.find('@');
    if (atPos != std::string::npos) {
        return fullUsername.substr(0, atPos);
    }
    return fullUsername;
}

std::string Analysis::FindAcls::getUserDistinguishedName(
    const std::string& username,
    const std::string& baseDN
) {
    std::string query = "(sAMAccountName=" + username + ")";
    std::vector<std::string> attrs = {"distinguishedName"};
    
    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attrs);
    
    if (results.empty()) {
        return "";
    }
    
    return results[0].at("distinguishedName").front();
}

void Analysis::FindAcls::collectUserSids(const std::string& userDN) {
    auto results = ldap.executeBaseScopeQueryAndUnpackData(
        userDN,
        "(objectClass=*)",
        {"objectSid", "tokenGroups"}
    );
    
    if (results.empty()) {
        return;
    }
    
    const auto& userEntry = results[0];
    
    addUserPrimarySid(userEntry);
    addUserGroupSids(userEntry);
}

void Analysis::FindAcls::addUserPrimarySid(const SingleLDAPResult& userEntry) {
    if (!userEntry.count("objectSid")) {
        return;
    }
    
    std::string sid = acl.sidToString(
        acl.decodeData(userEntry.at("objectSid").front())
    );
    
    mySids.insert(sid);
    
    std::string shortUsername = extractShortUsername(myUsername);
    sidNameCache[sid] = shortUsername;
}

void Analysis::FindAcls::addUserGroupSids(const SingleLDAPResult& userEntry) {
    if (!userEntry.count("tokenGroups")) {
        return;
    }
    
    for (const auto& encodedSid : userEntry.at("tokenGroups")) {
        std::string groupSid = acl.sidToString(acl.decodeData(encodedSid));
        mySids.insert(groupSid);
    }
}

inline void Analysis::FindAcls::addWellKnownSids() {
    mySids.insert("S-1-1-0");   // Everyone
    mySids.insert("S-1-5-11");  // Authenticated Users
}

void Analysis::FindAcls::displayTargetAcls(
    const std::string& target,
    const std::vector<AclEntry>& aclEntries
) const {
    std::cout << "\n[" << Colors::COLOR_BLUE << target << Colors::COLOR_RESET << "]\n";
    
    for (const auto& entry : aclEntries) {
        displaySingleAclEntry(entry);
    }
}

void Analysis::FindAcls::displaySingleAclEntry(const AclEntry& entry) const {
    // Format: [Victim]
    //   TRUSTEE_NAME → permission1, permission2, permission3"
    std::cout << "  ";
    
    if (entry.isInherited) {
        std::cout << Colors::COLOR_YELLOW << "Group Delegated" << Colors::COLOR_RESET << std::endl;
        std::cout << "  ";
    }
    if (entry.trusteeName != entry.trusteeSid) {
        std::cout << Colors::COLOR_GREEN << entry.trusteeName << Colors::COLOR_RESET;
    } else {
        std::cout << entry.trusteeSid;
    }

    std::cout << "  ->  ";
    
    displayPermissionList(entry.permissions);
    
    std::cout << "\n";
}

void Analysis::FindAcls::displayPermissionList(const std::vector<std::string>& permissions) const {
    for (size_t i = 0; i < permissions.size(); ++i) {
        const char* color = getPermissionColor(permissions[i]);
        std::cout << color << permissions[i] << Colors::COLOR_RESET;
        
        if (i < permissions.size() - 1) {
            std::cout << ", ";
        }
    }
}

inline void Analysis::FindAcls::displayUserNotFoundError(const std::string& username) const {
    std::cerr << Colors::COLOR_RED 
              << "[-] Error: Could not find user " << username 
              << ". Filtering disabled." 
              << Colors::COLOR_RESET << std::endl;
}

inline void Analysis::FindAcls::displaySecurityDescriptorError(const std::string& target) const {
    std::cerr << Colors::COLOR_RED 
              << "[-] Warning: Could not read nTSecurityDescriptor for " << target 
              << Colors::COLOR_RESET << std::endl;
}