#include "protocols/LdapResultParser.h"

#include <ldap.h>

#include "utils/Encoding.h"

namespace {

// Printable values are returned as-is; binary values are emitted as
// "::<base64>" so downstream code can recognise and decode them.
std::string encodeAttributeValue(const berval* value) {
    const char* data = value->bv_val;
    const size_t length = value->bv_len;

    if (Encoding::isPrintable(data, length)) {
        return std::string(data, length);
    }
    return "::" + Encoding::base64Encode(data, length);
}

std::vector<std::string> extractAttributeValues(LDAP* session, LDAPMessage* entry,
                                                const char* attributeName) {
    std::vector<std::string> values;
    berval** rawValues = ldap_get_values_len(session, entry, attributeName);
    if (rawValues == nullptr) {
        return values;
    }

    for (size_t i = 0; rawValues[i] != nullptr; ++i) {
        values.push_back(encodeAttributeValue(rawValues[i]));
    }

    ldap_value_free_len(rawValues);
    return values;
}

SingleLDAPResult processEntry(LDAP* session, LDAPMessage* entry) {
    SingleLDAPResult entryData;
    BerElement* ber = nullptr;

    for (char* attrName = ldap_first_attribute(session, entry, &ber);
         attrName != nullptr;
         attrName = ldap_next_attribute(session, entry, ber)) {
        entryData[attrName] = extractAttributeValues(session, entry, attrName);
        ldap_memfree(attrName);
    }

    if (ber != nullptr) {
        ber_free(ber, 0);
    }

    return entryData;
}

}  // namespace

namespace LdapResultParser {

LDAPResult parse(LDAP* session, LDAPMessage* result) {
    LDAPResult results;
    if (result == nullptr || session == nullptr) {
        return results;
    }

    for (LDAPMessage* entry = ldap_first_entry(session, result);
         entry != nullptr;
         entry = ldap_next_entry(session, entry)) {
        results.push_back(processEntry(session, entry));
    }

    return results;
}

}  // namespace LdapResultParser
