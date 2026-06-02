#pragma once
#include "core/Module.h"
#include "protocols/LdapConnection.h"
#include "cli/ArgumentParser.h"
#include "protocols/KerberosInteraction.h"
#include "core/Context.h"

namespace Attacks {
    class Kerberoast : public Module {
        private:
            LdapQuerier& ldap;
            KerberosInteraction& krb;
            std::string username;
            std::string password;
    
            std::vector<std::string> listUser(const std::string& baseDN);
            std::pair<std::string, std::string> requestTicket(const std::string& spn);
    
        public:
            Kerberoast(LdapQuerier& ldap_,
                        KerberosInteraction& krb_,
                        const std::string& user_,
                        const std::string& pass_
                    );
            std::string getName() const override { return "Kerberoast"; }
            void run(const ModuleRuntimeContext& ctx) override;
        };

    class ASREPRoast : public Module{
        LdapQuerier& ldap;

        std::string extractDomainFromDN(const std::string& baseDN);
        public:
        ASREPRoast(LdapQuerier& ldap);
        std::vector<std::string> listUser(const std::string& baseDN);
        bool requestTicket(const std::string& vuln_user, const std::string& domain);

        std::string getName() const override { return "ASREPRoast"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };
};