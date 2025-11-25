#include <iostream>
#include <iomanip>
#include <ctime>
#include <string>
#include <algorithm>
#include "Analysis.h"
#include "../../utils/Colors.h"

static std::string filetimeToString(const std::string& filetimeStr) {
    try {
        unsigned long long filetime = std::stoull(filetimeStr);
        if (filetime == 0 || filetime == 9223372036854775807) return "Never";
        time_t unixTime = (filetime / 10000000ULL) - 11644473600ULL;
        
        char buffer[80];
        struct tm* timeinfo = localtime(&unixTime);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buffer);
    } catch (...) { return "Invalid Date"; }
}

static std::string extractCN(const std::string& dn) {
    size_t start = dn.find("CN=");
    if (start == std::string::npos) return dn;
    start += 3;
    size_t end = dn.find(',', start);
    if (end == std::string::npos) return dn.substr(start);
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

Analysis::Whoami::Whoami(I_LdapQuerier& ldap_, const std::string& username_) 
    : ldap(ldap_), username(username_) {}

void Analysis::Whoami::run(const ModuleRuntimeContext& ctx) {
    std::cout << "[*] Querying LDAP for current user metadata..." << std::endl;

    std::string shortUsername = username;
    size_t pos = shortUsername.find("@");
    if (pos != std::string::npos) {
        shortUsername = shortUsername.substr(0, pos);
    }

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

    auto results = ldap.executeQuery(ctx.baseDN, query, attributes);

    if (results.empty()) {
        std::cerr << Colors::COLOR_RED << "[-] Error: Could not find user object '" 
                  << shortUsername << "' in base '" << ctx.baseDN << "'" 
                  << Colors::COLOR_RESET << std::endl;
        return;
    }
    
    const auto& me = results[0];

    
    std::cout << "\n" << Colors::COLOR_GREEN << "=== WHOAMI: " << shortUsername << " ===" << Colors::COLOR_RESET << "\n";

    auto printAttr = [&](const char* label, const std::string& key, bool isDate = false, bool isUAC = false) {
        if (me.count(key) && !me.at(key).empty()) {
            std::string val = me.at(key).front();
            
            if (isDate) val = filetimeToString(val);
            if (isUAC)  val = decodeUAC(val) + " (" + val + ")";
            
            std::cout << std::left << std::setw(20) << label << ": " << val << "\n";
        }
    };

    printAttr("Distinguished Name", "distinguishedName");
    printAttr("Description",        "description");
    printAttr("SID",                "objectSid"); // Virá em Base64/Binário até usarmos libndr
    printAttr("Account Status",     "userAccountControl", false, true);
    printAttr("Password Last Set",  "pwdLastSet", true);
    printAttr("Last Logon",         "lastLogon", true);

    if (me.count("adminCount")) {
        std::string val = me.at("adminCount").front();
        if (val == "1") {
            std::cout << std::left << std::setw(20) << "Privileges" << ": " 
                      << Colors::COLOR_RED << "HIGH VALUE TARGET (AdminCount=1)" << Colors::COLOR_RESET << "\n";
        }
    }

    std::cout << "\n" << Colors::COLOR_YELLOW << "--- Group Membership ---" << Colors::COLOR_RESET << "\n";

    if (me.count("primaryGroupID")) {
        std::string pgid = me.at("primaryGroupID").front();
        std::string groupName;
        
        if (pgid == "513") groupName = "Domain Users";
        else if (pgid == "512") groupName = "Domain Admins";
        else if (pgid == "514") groupName = "Domain Guests";
        else if (pgid == "515") groupName = "Domain Computers";
        else if (pgid == "516") groupName = "Domain Controllers";
        else groupName = "RID-" + pgid;

        std::cout << "  * " << groupName << " (Primary Group)\n";
    }

    if (me.count("memberOf")) {
        for (const auto& groupDN : me.at("memberOf")) {
            std::cout << "  - " << extractCN(groupDN) << "\n";
        }
    }
    
    std::cout << "\n";
}