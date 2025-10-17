#pragma once

#include <string>
#include <vector>
#include <map>

struct ldap;
typedef struct ldap LDAP;

class LDAPConnection {
private:
    LDAP* m_ldapSession;
    bool m_isConnected;
    bool m_isAuthenticated;

public:
    LDAPConnection();
    ~LDAPConnection();

    bool connect(const std::string& host, unsigned short port = 389);
    bool bind(const std::string& username, const std::string& password);
    void disconnect();
    std::vector<std::map<std::string, std::vector<std::string>>> executeQuery(const std::string& baseDN, const std::string& query, const std::vector<std::string>& attributes);

    bool isConnected() const;
    bool isAuthenticated() const;
};