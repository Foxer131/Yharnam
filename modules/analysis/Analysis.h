#pragma once
#include "../../core/I_Module.h"
#include "../../protocols/I_LdapQuerier.h"
#include "../../protocols/AclService.h"
#include <vector>
#include <string>
#include <set>
#include <map>

namespace Analysis {
    class Query : public I_Module {
    private:
        I_LdapQuerier& ldap;
        std::string queryFilter;
        std::vector<std::string> attributesToFetch;

        void displayResults(const LDAPResult& result);

    public:
        Query(I_LdapQuerier& _ldap, 
                const std::string& _query, 
                const std::vector<std::string>& _attrs
            );

        std::string getName() const override { return "Custom LDAP Query"; }
        
        void run(const ModuleRuntimeContext& ctx) override;
    };

    class Whoami : public I_Module {
        I_LdapQuerier& ldap;
        std::string username;

    public:
        Whoami(I_LdapQuerier& _ldap, const std::string& _username);

        std::string getName() const override { return "Whoami"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };

    class FindAcls : public I_Module {
        I_LdapQuerier& ldap;
        AclService& acl;

        bool scanAll = false;
        std::string myUsername;
        std::set<std::string> mySids;
        std::map<std::string, std::string> sidNameCache;
        std::vector<std::string> targets;

        void checkTarget(const std::string& targetName, const std::string& baseDN);
        std::string resolveSid(const std::string& sidStr, const std::string& baseDN);
        void populateMySids(const std::string& baseDN);
        std::vector<std::string> enumerateAllUsers(const std::string& baseDN);
    public:
        FindAcls(I_LdapQuerier& ldap_, 
                AclService& acl_, 
                const std::string& username_, 
                const std::vector<std::string>& customTargets_ = {},
                bool scanAll_ = false
            );

        std::string getName() const override { return "Find ACLs"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };
}