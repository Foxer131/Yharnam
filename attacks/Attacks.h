#pragma once

#include <vector>
#include <string>
#include "../connections/LDAPConnection.h"

enum AttackMethod {
    KERBEROAST,
    ASREPROAST,
    GOLDEN_TICKET,
    DCSYNC,
    NONE
};

namespace Attacks {
    class Kerberoast {
        LDAPConnection& conn;
    public:
        Kerberoast(LDAPConnection& _conn);
        std::vector<std::string> listUser(const std::string& baseDN);
        std::string requestTicket(const std::vector<std::string>& spns);
        std::pair<std::string, std::string> requestTicket(const std::string& spn, const std::string& username, bool to_file);
    };

    class ASREPRoast {
        LDAPConnection& conn;
    public:
        ASREPRoast(LDAPConnection& _conn);
        std::vector<std::string> listUser(const std::string& baseDN);
        std::string requestTicket(std::vector<std::string>);
        bool requestTicket(const std::string& vuln_user);
    };
};

