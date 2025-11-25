#pragma once
#include "../../core/I_Module.h"
#include "../../protocols/LDAPConnection.h"
#include "../../cli/ArgumentParser.h"
#include "../../protocols/KerberosInteraction.h"
#include "../../core/Context.h"

namespace Attacks {
    class Kerberoast : public I_Module {
        private:
            I_LdapQuerier& ldap;
            KerberosInteraction& krb;
            std::string username;
            std::string password;
    
            std::vector<std::string> listUser(const std::string& baseDN);
            std::pair<std::string, std::string> requestTicket(const std::string& spn);
    
        public:
            Kerberoast(I_LdapQuerier& _ldap, 
                        KerberosInteraction& _krb, 
                        const std::string& user, 
                        const std::string& pass
                    );
            std::string getName() const override { return "Kerberoast"; }
            void run(const ModuleRuntimeContext& ctx) override;
        };

    class ASREPRoast : public I_Module{
        I_LdapQuerier& ldap;

        std::string extractDomainFromDN(const std::string& baseDN);
        public:
        ASREPRoast(I_LdapQuerier& ldap);
        std::vector<std::string> listUser(const std::string& baseDN);
        bool requestTicket(const std::string& vuln_user, const std::string& domain);

        std::string getName() const override { return "ASREPRoast"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };
};