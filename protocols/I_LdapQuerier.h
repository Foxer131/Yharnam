#pragma once
#include <string>
#include <vector>
#include <map>

using LDAPResult = std::vector<std::map<std::string, std::vector<std::string>>>;

class I_LdapQuerier {
public:
    virtual ~I_LdapQuerier() = default;
    
    virtual LDAPResult executeQuery(const std::string& baseDN,
                                    const std::string& query,
                                    const std::vector<std::string>& attributes) = 0;
    
    virtual LDAPResult executeBaseQuery(const std::string& baseDN,
                                        const std::string& query,
                                        const std::vector<std::string>& attributes) = 0;
};