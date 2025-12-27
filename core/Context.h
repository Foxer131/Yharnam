#pragma once
#include <string>
#include "../cli/ArgumentParser.h" 

class LdapConnection;    
class KerberosInteraction;
class LdapQuerier;
class AclService;

struct ModuleFactoryContext {
    const Modules moduleToRun;
    LdapConnection& ldapService;
    KerberosInteraction& krbService;
    AclService& aclService;
    const User& user;
    const std::string query;
    const std::vector<std::string> attrs;
    std::vector<std::string> customTargets;
    bool scanAll;

    ModuleFactoryContext(Modules mod, 
        LdapConnection& l, 
        KerberosInteraction& k, 
        AclService& a, 
        const User& u, 
        const std::string& q = "", 
        const std::vector<std::string>& att = {},
        const std::vector<std::string>& targets = {},
        bool all = false
    ) : moduleToRun(mod), ldapService(l), krbService(k), aclService(a), user(u), 
    query(q), attrs(att), customTargets(targets), scanAll(all) {}
};

struct ModuleRuntimeContext {
    LdapQuerier& ldap;
    const std::string& baseDN;
    const std::string& outputFilePath;

    ModuleRuntimeContext(LdapQuerier& l, const std::string& dn, const std::string& path)
        : ldap(l), baseDN(dn), outputFilePath(path) {}
};