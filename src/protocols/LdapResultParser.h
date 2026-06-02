#pragma once
#include "protocols/LdapQuerier.h"

typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;

// Converts the raw LDAP messages returned by libldap into the plain
// attribute/value maps the rest of Yharnam works with. Kept separate from
// LdapConnection so result decoding has a single responsibility and can be
// reused or tested without an open connection.
namespace LdapResultParser {

/// @brief Decodes every entry in @p result into an LDAPResult.
/// @param session The LDAP* the result was produced on (used for iteration).
LDAPResult parse(LDAP* session, LDAPMessage* result);

}  // namespace LdapResultParser
