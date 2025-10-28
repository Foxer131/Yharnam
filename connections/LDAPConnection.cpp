#include "LDAPConnection.h"
#include <iostream>
#include <ldap.h>
#include <map>

bool is_printable(const char* data, size_t len);
std::string base64_encode(const char* data, size_t len);

LDAPConnection::LDAPConnection() : m_ldapSession(nullptr), m_isAuthenticated(false), m_isConnected(false) {}

LDAPConnection::~LDAPConnection() { disconnect(); }

bool LDAPConnection::connect(const std::string& host, unsigned short port) {
    if (m_isConnected) {
        disconnect();
    }

    std::string ldap_uri = "ldap://" + host + ":" + std::to_string(port);
    int rc = ldap_initialize(&m_ldapSession, ldap_uri.c_str());

    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to initialize LDAP session: " << ldap_err2string(rc) << std::endl;
        m_ldapSession = nullptr;
        return false;
    }

    int ldapVersion = LDAP_VERSION3;
    rc = ldap_set_option(m_ldapSession, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to set LDAP protocol version: " << ldap_err2string(rc) << std::endl;
        ldap_unbind_ext_s(m_ldapSession, NULL, NULL);
        m_ldapSession = nullptr;
        return false;
    }

    int chase_referrals = 0;
    ldap_set_option(m_ldapSession, LDAP_OPT_REFERRALS, &chase_referrals);

    m_isConnected = true;
    return true;
}

void LDAPConnection::disconnect() {
    if (m_ldapSession != nullptr) {
        ldap_unbind_ext_s(m_ldapSession, NULL, NULL);
        m_ldapSession = nullptr;
    }
    m_isConnected = false;
    m_isAuthenticated = false;
}

bool LDAPConnection::bind(const std::string& username, const std::string& password) {
    if (!m_isConnected) {
        std::cerr << "LDAPConnection::bind: Not connected" << std::endl;
        return false;
    }

    struct berval creds;
    creds.bv_val = (char*)password.c_str();
    creds.bv_len = password.length();

    int returnCode = ldap_sasl_bind_s(
        m_ldapSession,
        username.c_str(),
        LDAP_SASL_SIMPLE,
        &creds,
        NULL,
        NULL,
        NULL
    );

    if (returnCode != LDAP_SUCCESS) {
        std::cerr << "LDAP bind failed: " << ldap_err2string(returnCode) << std::endl;
        return false;
    }
    m_isAuthenticated = true;
    return true;
}

bool LDAPConnection::isAuthenticated() const { return m_isAuthenticated; }
bool LDAPConnection::isConnected() const { return m_isConnected; }

std::vector<std::map<std::string, std::vector<std::string>>> LDAPConnection::executeQuery(const std::string& baseDN, const std::string& query, const std::vector<std::string>& attributes) {
    std::vector<std::map<std::string, std::vector<std::string>>> results;
    
    if (!m_isConnected || !m_isAuthenticated)
        return results;

    LDAPMessage* res = nullptr;
    std::vector<char*> attr;
    for (const auto& attribute : attributes) {
        attr.push_back(const_cast<char*>(attribute.c_str()));
    }
    attr.push_back(NULL);

    int chase_referrals = 0;
    ldap_set_option(m_ldapSession, LDAP_OPT_REFERRALS, &chase_referrals);

    int returnCode = ldap_search_ext_s(m_ldapSession, baseDN.c_str(), LDAP_SCOPE_SUBTREE, query.c_str(), attr.data(), 0, NULL, NULL, NULL, 0, &res);

    if (res != NULL) {
        for (LDAPMessage* entry = ldap_first_entry(m_ldapSession, res); entry != NULL; entry = ldap_next_entry(m_ldapSession, entry)) {
            
            std::map<std::string, std::vector<std::string>> currentObject;
            BerElement* ber = nullptr;
            for (char* attribute_name = ldap_first_attribute(m_ldapSession, entry, &ber);
                attribute_name != NULL;
                attribute_name = ldap_next_attribute(m_ldapSession, entry, ber)) {
                
                std::vector<std::string> currentAttr_values;
                berval** values = ldap_get_values_len(m_ldapSession, entry, attribute_name);
                if (values != NULL) {
                    for (int i = 0; values[i] != NULL; i++) {
                        const char* value_data = values[i]->bv_val;
                        size_t value_len = values[i]->bv_len;

                        if (is_printable(value_data, value_len)) {
                            currentAttr_values.push_back(value_data);
                        } else {
                            currentAttr_values.push_back("::" + base64_encode(value_data, value_len));
                        }
                    }
                    ldap_value_free_len(values);
                }
                currentObject[attribute_name] = currentAttr_values;
                ldap_memfree(attribute_name);
            }
            if (ber != NULL) {
                ber_free(ber, 0);
            }

            results.push_back(currentObject);
        }
    }

    if (returnCode != LDAP_SUCCESS && results.empty()) {
        std::cerr << "LDAP Search Error: " << ldap_err2string(returnCode) << std::endl;
    }

    if (res) {
        ldap_msgfree(res);
    }
    return results;
}


bool is_printable(const char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!isprint(static_cast<unsigned char>(data[i]))) {
            return false;
        }
    }
    return true;
}

std::string base64_encode(const char* data, size_t len) {
    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }
    return ret;
}