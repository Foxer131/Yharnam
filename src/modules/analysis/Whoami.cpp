#include <iostream>
#include <iomanip>
#include <ctime>
#include <string>
#include <algorithm>
#include "Analysis.h"
#include "utils/Colors.h"
#include "utils/StringUtils.h"
#include "protocols/AclService.h"
#include "cli/ArgumentParser.h"
#include "core/ActiveDirectory.h"
#include "core/ModuleRegistry.h"

namespace {
const ModuleRegistry::Registrar registrar(
    Modules::WHOAMI,
    [](const ModuleFactoryContext& ctx) -> std::unique_ptr<Module> {
        return std::make_unique<Analysis::Whoami>(ctx.ldapService, ctx.user.username);
    });
}  // namespace

// Windows FILETIME counts 100-nanosecond ticks since 1601-01-01 UTC.
namespace {
constexpr unsigned long long kFiletimeTicksPerSecond = 10000000ULL;
constexpr unsigned long long kFiletimeToUnixEpochSeconds = 11644473600ULL;
constexpr unsigned long long kFiletimeNever = 9223372036854775807ULL;  // INT64_MAX
}  // namespace

static std::string filetimeToString(const std::string& filetimeStr) {
    try {
        unsigned long long filetime = std::stoull(filetimeStr);

        if (filetime == 0 || filetime == kFiletimeNever)
            return "Never";
        time_t unixTime = (filetime / kFiletimeTicksPerSecond) - kFiletimeToUnixEpochSeconds;

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
        if (uac & AD::Uac::Disabled)             status += "[DISABLED] ";
        if (uac & AD::Uac::LockedOut)            status += "[LOCKED_OUT] ";
        if (uac & AD::Uac::PasswdNotRequired)    status += "[PASSWD_NOTREQD] ";
        if (uac & AD::Uac::DontExpirePassword)   status += "[DONT_EXPIRE_PASSWD] ";
        if (uac & AD::Uac::TrustedForDelegation) status += "[TRUSTED_FOR_DELEGATION] ";

        return status.empty() ? "Normal (Enabled)" : status;
    } catch (...) { return uacStr; }
}

Analysis::Whoami::Whoami(LdapQuerier& ldap_, const std::string& username_) 
    : ldap(ldap_), 
    username(username_) 
{}

void Analysis::Whoami::run(const ModuleRuntimeContext& ctx) {
    std::cout << "[*] Querying LDAP for current user metadata..." << std::endl;

    std::string shortUsername = StringUtils::shortUsername(username);

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

    printAttribute(userData, "objectSid",         "SID",             AttrFormat::Sid);

    printAttribute(userData, "userAccountControl", "Account Status", AttrFormat::Uac);
    printAttribute(userData, "pwdLastSet",         "Password Last Set", AttrFormat::Date);
    printAttribute(userData, "lastLogon",          "Last Logon",     AttrFormat::Date);

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
    AttrFormat format
) const {
    if (!data.count(key) || data.at(key).empty())
        return;

    std::string val = data.at(key).front();

    switch (format) {
        case AttrFormat::Date:
            val = filetimeToString(val);
            break;
        case AttrFormat::Uac:
            val = decodeUAC(val) + " (" + val + ")";
            break;
        case AttrFormat::Sid:
            val = AclService::sidToString(AclService::decodeData(val));
            break;
        case AttrFormat::Raw:
            break;
    }

    std::cout << std::left << std::setw(20) << label << ": " << val << "\n";
}

std::string Analysis::Whoami::resolvePrimaryGroup(const std::string& rid) const {
    return AD::primaryGroupName(rid);
}

