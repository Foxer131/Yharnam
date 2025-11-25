#pragma once

#include <string>
#include <vector>
#include <map>
#include "I_LdapQuerier.h"

struct ldap;
typedef struct ldap LDAP;

class LDAPConnection : public I_LdapQuerier{
private:
    LDAP* m_ldapSession;
    bool m_isConnected;
    bool m_isAuthenticated;

    LDAPResult performSearch(const std::string& baseDN, int scope, 
                            const std::string& query, 
                            const std::vector<std::string>& attributes);
public:
    LDAPConnection();
    ~LDAPConnection();

    bool connect(const std::string& host, unsigned short port = 389);
    bool bind(const std::string& username, const std::string& password);
    void disconnect();
    LDAPResult executeQuery(const std::string& baseDN, const std::string& query, const std::vector<std::string>& attributes) override;
    LDAPResult executeBaseQuery(const std::string& baseDN, const std::string& query, const std::vector<std::string>& attributes) override;
    bool isConnected() const;
    bool isAuthenticated() const;
};