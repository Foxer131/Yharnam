#pragma once

#include <vector>
#include <string>
#include "LDAPConnection.h"

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
        bool requestTicket(const std::string& spn, const std::string& username, const std::string& password);
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

