#pragma once
#include <vector>
#include <string>
#include <set>
#include <map>
#include "../../core/Module.h"       
#include "../../protocols/LdapQuerier.h" 
#include "../../protocols/AclService.h"

namespace Analysis {
    
    class Query : public Module {
    private:
        LdapQuerier& ldap;
        std::string queryFilter;
        std::vector<std::string> attributesToFetch;

        void displayResults(const LDAPResult& result);

    public:
        Query(LdapQuerier& _ldap, 
                const std::string& _query, 
                const std::vector<std::string>& _attrs
            );

        std::string getName() const override { return "Custom LDAP Query"; }
        
        void run(const ModuleRuntimeContext& ctx) override;
    };
    
    class Whoami : public Module {
    private:
        LdapQuerier& ldap;
        std::string username;

        std::string extractShortUsername(const std::string& fullUsername) const;
        SingleLDAPResult fetchCurrentUser(const std::string& shortUser, const std::string& baseDN);
        
        void displayUserMetadata(const SingleLDAPResult& userData) const;
        void displayGroupMembership(const SingleLDAPResult& userData) const;
        
        void printAttribute(
            const SingleLDAPResult& data, 
            const std::string& key, 
            const std::string& label, 
            bool isDate = false, 
            bool isUAC = false,
            bool isSid = false
        ) const;
        std::string resolvePrimaryGroup(const std::string& rid) const;

    public:
        Whoami(LdapQuerier& _ldap, const std::string& _username);

        std::string getName() const override { return "Whoami"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };

    class FindAcls : public Module {
    private:
        LdapQuerier& ldap;
        AclService& acl;
            
        bool scanAll;
        std::string myUsername;
        std::vector<std::string> targets;
            
        std::set<std::string> mySids;
        std::map<std::string, std::string> sidNameCache;
            
        struct AclEntry {
            std::string trusteeSid;
            std::string trusteeName;
            std::vector<std::string> permissions;
            bool isInherited;
        };
            
        void scanTargetAcls(const std::string& targetName, const std::string& baseDN);
        std::string fetchTargetSecurityDescriptor(const std::string& target, const std::string& baseDN);
        std::vector<AclEntry> filterRelevantAcls(const std::vector<Security::Ace>& aces, const std::string& baseDN);
            
        bool shouldSkipAce(const Security::Ace& ace) const;
        bool isSystemAccount(const std::string& sid) const;
        bool isWellKnownPublicSid(const std::string& sid) const;
        bool isNoisePermission(const Security::Ace& ace, const std::vector<std::string>& permissions) const;
            
        std::string resolveSid(const std::string& sidStr, const std::string& baseDN);
        std::string resolveWellKnownSid(const std::string& sidStr) const;
        std::string resolveNotKnownSid(const std::string& baseDN, const std::string& sidStr);
            
        void populateMySids(const std::string& baseDN);
        std::vector<std::string> enumerateAllUsers(const std::string& baseDN);
            
        std::string buildUserEnumerationQuery() const;
        std::vector<std::string> extractUserNamesFromResults(const LDAPResult& results) const;
        std::string extractShortUsername(const std::string& fullUsername) const;
        std::string getUserDistinguishedName(const std::string& username, const std::string& baseDN);
        
        void collectUserSids(const std::string& userDN);
        void addUserPrimarySid(const SingleLDAPResult& userEntry);
        void addUserGroupSids(const SingleLDAPResult& userEntry);
        void addWellKnownSids();
            
        void displayTargetAcls(const std::string& target, const std::vector<AclEntry>& aclEntries) const;
        void displaySingleAclEntry(const AclEntry& entry) const;
        void displayPermissionList(const std::vector<std::string>& permissions) const;
        void displayUserNotFoundError(const std::string& username) const;
        void displaySecurityDescriptorError(const std::string& target) const;
        
    public:
        FindAcls(
            LdapQuerier& ldap_, 
            AclService& acl_, 
            const std::string& username_, 
            const std::vector<std::string>& customTargets_ = {},
            bool scanAll_ = false
        );
        ~FindAcls() = default;
            
        std::string getName() const override { return "Find ACLs"; }
        void run(const ModuleRuntimeContext& ctx) override;
    };
}