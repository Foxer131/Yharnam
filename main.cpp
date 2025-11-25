#include <iostream>
#include <vector>
#include <string>
#include <ldap.h>
#include "protocols/LDAPConnection.h"
#include "protocols/KerberosInteraction.h"
#include "protocols/AclService.h"
#include "cli/ArgumentParser.h"
#include "modules/attacks/Attacks.h"
#include "utils/Utils.h"
#include "utils/Colors.h"
#include "core/ModuleGenerator.h"
#include "core/I_Module.h"
#include "core/ModuleGenerator.h"
#include "core/Context.h"


int main(int argc, char* argv[]) {
    ArgumentParser parser;
    if (!parser.parse(argc, argv))
        return 0;

    try {
        
        LDAPConnection ldap; 
        std::string targetIP = parser.getIP();

        if (!ldap.connect(targetIP)) {
            std::cerr << Colors::COLOR_RED << "[-] Failed to connect to LDAP at " << targetIP << Colors::COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << Colors::COLOR_BLUE << "[+] Connection established \t\t" << targetIP << Colors::COLOR_RESET << std::endl;

        User user = parser.getUser();
        if (!ldap.bind(user.username, user.password)) {
            std::cerr << Colors::COLOR_RED << "[-] Authentication failed for " << user.username << Colors::COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << Colors::COLOR_GREEN << "[*] Authenticated successfully \t" << user.username << Colors::COLOR_RESET << std::endl;

        KerberosInteraction krbService;
        AclService acl;

        ModuleFactoryContext factoryCtx(
            parser.getModuleToRun(),
            ldap,
            krbService,
            acl,
            user,
            parser.getQuery(),
            parser.getAttributes(),
            parser.getCustomTargets(),
            parser.getScanAll()
        );

        std::unique_ptr<I_Module> module = ModuleFactory::createModule(factoryCtx);

        if (module) {
            std::string baseDN = parser.makeBaseDN();
            ModuleRuntimeContext runtimeCtx(
                ldap, 
                baseDN,
                parser.getFilePath()
            );

            module->run(runtimeCtx);

        } else {
            if (parser.getModuleToRun() != Module::NONE) {
                std::cerr << Colors::COLOR_RED << "[-] Error: Failed to initialize the selected module." << Colors::COLOR_RESET << std::endl;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << Colors::COLOR_RED << "\n[!] Critical Error: " << e.what() << Colors::COLOR_RESET << std::endl;
        return 1;
    }

    std::cout << "\nEyes..." << std::endl;
    return 0;
}