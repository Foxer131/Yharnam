#include <iostream>
#include <iomanip>
#include <ctime>
#include <string>
#include <algorithm>
#include "Analysis.h"
#include "../../utils/Colors.h"
#include "../../protocols/AclService.h"

static std::string filetimeToString(const std::string& filetimeStr) {
    try {
        unsigned long long filetime = std::stoull(filetimeStr);

        if (filetime == 0 || filetime == 9223372036854775807) 
            return "Never";
        time_t unixTime = (filetime / 10000000ULL) - 11644473600ULL;
        
        char buffer[80];
        struct tm* timeinfo = localtime(&unixTime);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        return std::string(buffer);
    } catch (...) { 
        return "Invalid Date"; 
    }
}

static std::string extractCN(const std::string& dn) {
    size_t start = dn.find("CN=");
    if (start == std::string::npos) 
        return dn;

    start += 3;
    size_t end = dn.find(',', start);

    if (end == std::string::npos) 
        return dn.substr(start);

    return dn.substr(start, end - start);
}

static std::string decodeUAC(const std::string& uacStr) {
    try {
        int uac = std::stoi(uacStr);
        std::string status;
        if (uac & 0x0002) status += "[DISABLED] ";
        if (uac & 0x0010) status += "[LOCKED_OUT] ";
        if (uac & 0x0020) status += "[PASSWD_NOTREQD] ";
        if (uac & 0x10000) status += "[DONT_EXPIRE_PASSWD] ";
        if (uac & 0x80000) status += "[TRUSTED_FOR_DELEGATION] ";
        
        return status.empty() ? "Normal (Enabled)" : status;
    } catch (...) { return uacStr; }
}

Analysis::Whoami::Whoami(LdapQuerier& ldap_, const std::string& username_) 
    : ldap(ldap_), 
    username(username_) 
{}

void Analysis::Whoami::run(const ModuleRuntimeContext& ctx) {
    std::cout << "[*] Querying LDAP for current user metadata..." << std::endl;

    std::string shortUsername = extractShortUsername(username);

    std::string query = "(sAMAccountName=" + shortUsername + ")";
    std::vector<std::string> attributes = {
        "distinguishedName",
        "description",
        "memberOf",          
        "pwdLastSet",        
        "lastLogon",         
        "adminCount",        
        "userAccountControl",
        "primaryGroupID",
        "objectSid"
    };

    auto whoami_data = fetchCurrentUser(shortUsername, ctx.baseDN);
    
    
    if (whoami_data.empty()) {
        std::cerr << Colors::COLOR_RED << "[-] Error: Could not find user object '" 
        << shortUsername << "' in base '" << ctx.baseDN << "'" 
        << Colors::COLOR_RESET << std::endl;
        return;
    }
    
    displayUserMetadata(whoami_data);
    displayGroupMembership(whoami_data);

    std::cout << "\n";
}

SingleLDAPResult Analysis::Whoami::fetchCurrentUser(
    const std::string& shortUser, 
    const std::string& baseDN
) {
    std::string query = "(sAMAccountName=" + shortUser + ")";
    std::vector<std::string> attributes = {
        "distinguishedName",
        "description",
        "memberOf",           
        "pwdLastSet",         
        "lastLogon",          
        "adminCount",         
        "userAccountControl",
        "primaryGroupID",
        "objectSid"
    };

    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attributes);

    if (results.empty()) {
        return {};
    }
    return results[0];
}

void Analysis::Whoami::displayUserMetadata(const SingleLDAPResult& userData) const {
    printAttribute(userData, "distinguishedName", "Distinguished Name");
    printAttribute(userData, "description",       "Description");
    
    printAttribute(userData, "objectSid",         "SID", false, false, true); 
    
    printAttribute(userData, "userAccountControl", "Account Status", false, true);
    printAttribute(userData, "pwdLastSet",         "Password Last Set", true);
    printAttribute(userData, "lastLogon",          "Last Logon", true);

    if (userData.count("adminCount") && !userData.at("adminCount").empty()) {
        if (userData.at("adminCount").front() == "1") {
            std::cout << std::left << std::setw(20) << "Privileges" << ": " 
                      << Colors::COLOR_RED << "HIGH VALUE TARGET (AdminCount=1)" 
                      << Colors::COLOR_RESET << "\n";
        }
    }
}

void Analysis::Whoami::displayGroupMembership(const SingleLDAPResult& userData) const {
    std::cout << "\n" << Colors::COLOR_YELLOW << "--- Group Membership ---" << Colors::COLOR_RESET << "\n";

    if (userData.count("primaryGroupID") && !userData.at("primaryGroupID").empty()) {
        std::string pgid = userData.at("primaryGroupID").front();
        std::string groupName = resolvePrimaryGroup(pgid);
        std::cout << "  * " << groupName << " (Primary Group)\n";
    }

    if (userData.count("memberOf")) {
        for (const auto& groupDN : userData.at("memberOf")) {
            std::cout << "  - " << extractCN(groupDN) << "\n";
        }
    }
}

void Analysis::Whoami::printAttribute(
    const SingleLDAPResult& data, 
    const std::string& key, 
    const std::string& label, 
    bool isDate, 
    bool isUAC,
    bool isSid
) const {
    if (!data.count(key) || data.at(key).empty()) 
        return;

    std::string val = data.at(key).front();
    
    if (isDate) {
        val = filetimeToString(val); 
    }
    if (isUAC) {
        val = decodeUAC(val) + " (" + val + ")";
    }
    if (isSid) {
        auto sidBytes = AclService::decodeData(val);
        val = AclService::sidToString(sidBytes);
    }
    
    std::cout << std::left << std::setw(20) << label << ": " << val << "\n";
}

std::string Analysis::Whoami::resolvePrimaryGroup(const std::string& rid) const {
    static const std::map<std::string, std::string> ridMap = {
        {"512", "Domain Admins"},
        {"513", "Domain Users"},
        {"514", "Domain Guests"},
        {"515", "Domain Computers"},
        {"516", "Domain Controllers"},
        {"518", "Schema Admins"},
        {"519", "Enterprise Admins"},
        {"520", "Group Policy Creator Owners"}
    };

    auto it = ridMap.find(rid);
    if (it != ridMap.end()) {
        return it->second;
    }
    return "RID-" + rid;
}

std::string Analysis::Whoami::extractShortUsername(const std::string& fullUsername) const {
    size_t pos = fullUsername.find("@");
    if (pos != std::string::npos)
        return fullUsername.substr(0, pos);
    return fullUsername;
}