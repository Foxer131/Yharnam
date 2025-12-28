#include <iostream>
#include <vector>
#include <string>
#include <ldap.h>
#include "protocols/LdapConnection.h"
#include "protocols/KerberosInteraction.h"
#include "protocols/AclService.h"
#include "cli/ArgumentParser.h"
#include "modules/attacks/Attacks.h"
#include "utils/Utils.h"
#include "utils/Colors.h"
#include "core/ModuleGenerator.h"
#include "core/Module.h"
#include "core/ModuleGenerator.h"
#include "core/Context.h"


int main(int argc, char* argv[]) {
    ArgumentParser parser;
    if (!parser.parse(argc, argv))
        return 0;

    try {
        
        LdapConnection ldap_connection; 
        std::string targetIP = parser.getIP();
        ldap_connection.initialize(targetIP);

        if (!ldap_connection.connect()) {
            std::cerr << Colors::COLOR_RED << "[-] Failed to initialize to LDAP at " << targetIP << Colors::COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << Colors::COLOR_BLUE << "[+] Connection established \t\t" << targetIP << Colors::COLOR_RESET << std::endl;

        User user = parser.getUser();
        
        if (!ldap_connection.login(user.username, user.password)) {
            std::cerr << Colors::COLOR_RED << "[-] Authentication failed for " << user.username << Colors::COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << Colors::COLOR_GREEN << "[*] Authenticated successfully \t\t" << user.username << Colors::COLOR_RESET << std::endl;

        KerberosInteraction krbService;
        AclService acl;

        ModuleFactoryContext factoryCtx(
            parser.getModuleToRun(),
            ldap_connection,
            krbService,
            acl,
            user,
            parser.getQuery(),
            parser.getAttributes(),
            parser.getCustomTargets(),
            parser.getScanAll()
        );

        std::unique_ptr<Module> module_running = ModuleFactory::createModule(factoryCtx);

        if (module_running) {
            std::string baseDN = parser.makeBaseDN();
            ModuleRuntimeContext runtimeCtx(
                ldap_connection, 
                baseDN,
                parser.getFilePath()
            );

            module_running->run(runtimeCtx);

        } else {
            if (parser.getModuleToRun() != Modules::NONE) {
                std::cerr << Colors::COLOR_RED << "[-] Error: Failed to initialize the selected module." << Colors::COLOR_RESET << std::endl;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << Colors::COLOR_RED << "\n[!] Critical Error: " << e.what() << Colors::COLOR_RESET << std::endl;
        return 1;
    }

    std::cout << "\nGood night hunter." << std::endl;
    return 0;
}