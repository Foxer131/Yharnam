#pragma once
#include <string>
#include "../cli/ArgumentParser.h" 

class LDAPConnection;    
class KerberosInteraction;
class I_LdapQuerier;
class AclService;

struct ModuleFactoryContext {
    const Module moduleToRun;
    LDAPConnection& ldapService;
    KerberosInteraction& krbService;
    AclService& aclService;
    const User& user;
    const std::string query;
    const std::vector<std::string> attrs;
    std::vector<std::string> customTargets;
    bool scanAll;

    ModuleFactoryContext(Module mod, 
        LDAPConnection& l, 
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
    I_LdapQuerier& ldap;
    const std::string& baseDN;
    const std::string& outputFilePath;

    ModuleRuntimeContext(I_LdapQuerier& l, const std::string& dn, const std::string& path)
        : ldap(l), baseDN(dn), outputFilePath(path) {}
};