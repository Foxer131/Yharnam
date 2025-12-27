#pragma once
#include <string>
#include <vector>
#include <map>

using LDAPResult = std::vector<std::map<std::string, std::vector<std::string>>>;

class LdapQuerier {
public:
    virtual ~LdapQuerier() = default;
    
    virtual LDAPResult executeQueryAndUnpackData(const std::string& baseDN,
                                    const std::string& query,
                                    const std::vector<std::string>& attributes) = 0;
    
    virtual LDAPResult executeBaseScopeQueryAndUnpackData(const std::string& baseDN,
                                        const std::string& query,
                                        const std::vector<std::string>& attributes) = 0;
};