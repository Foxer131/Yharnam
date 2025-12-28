#include "LdapConnection.h"
#include <iostream>
#include <ldap.h>
#include <map>
#include <cstring>

inline bool is_printable(const char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (!isprint(static_cast<unsigned char>(data[i]))) {
            return false;
        }
    }
    return true;
}

std::string base64_encode(const char* data, size_t len) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::string ret;
    ret.reserve(((len + 2) / 3) * 4);
    
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

            for (i = 0; i < 4; i++)
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

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }
    return ret;
}


LdapConnection::LdapConnection() 
    : ldapSession(nullptr)
    , isAuthenticated_(false)
    , isConnected_(false) 
{}

LdapConnection::~LdapConnection() { 
    disconnect(); 
}

bool LdapConnection::initialize(const std::string& host, unsigned short port) {
    if (isConnected_) {
        disconnect();
    }

    if (!initializeLdapSession(host, port)) {
        return false;
    }

    if (!configureLdapOptions()) {
        cleanup();
        return false;
    }

    return true;
}

bool LdapConnection::connect() {
    if (ldapSession == nullptr) {
        std::cerr << "LDAP Session not initialized. Call initialize() first." << std::endl;
        return false;
    }

    std::vector<char*> attrs = {
        (char*)"defaultNamingContext",
        (char*)"dnsHostName",
        nullptr
    };

    LDAPMessage* res = nullptr;

    int rc = executeLdapSearch(
        "",                 
        LDAP_SCOPE_BASE,    
        "(objectClass=*)",  
        attrs,              
        nullptr,            
        &res               
    );

    cleanupSearchResources(res);

    if (rc == LDAP_SUCCESS || rc == LDAP_OPERATIONS_ERROR || rc == LDAP_STRONG_AUTH_REQUIRED) {
        isConnected_ = true;
        return true;
    }

    std::cerr << "[-] Connection probe failed: " << ldap_err2string(rc) << std::endl;
    isConnected_ = false;
    return false;
}

void LdapConnection::disconnect() {
    cleanup();
    isConnected_ = false;
    isAuthenticated_ = false;
}

bool LdapConnection::login(const std::string& username, const std::string& password) {
    if (!isConnected_) {
        std::cerr << "LdapConnection::login: Not connected" << std::endl;
        return false;
    }

    struct berval creds = createCredentials(password);
    
    int returnCode = ldap_sasl_bind_s(
        ldapSession,
        username.c_str(),
        LDAP_SASL_SIMPLE,
        &creds,
        NULL,
        NULL,
        NULL
    );

    if (returnCode != LDAP_SUCCESS) {
        return false;
    }
    
    isAuthenticated_ = true;
    return true;
}

LDAPResult LdapConnection::executeBaseScopeQueryAndUnpackData(
    const std::string& baseDN, 
    const std::string& query, 
    const std::vector<std::string>& attributes) 
{
    return performSpecifiedScopeSearch(baseDN, LDAP_SCOPE_BASE, query, attributes);
}

LDAPResult LdapConnection::executeQueryAndUnpackData(
    const std::string& baseDN, 
    const std::string& query, 
    const std::vector<std::string>& attributes) 
{
    return performSpecifiedScopeSearch(baseDN, LDAP_SCOPE_SUBTREE, query, attributes);
}

LDAPResult LdapConnection::performSpecifiedScopeSearch(
    const std::string& baseDN, 
    int scope, 
    const std::string& query, 
    const std::vector<std::string>& attributes
) {
    if (!isConnected_ || !isAuthenticated_) {
        return LDAPResult();
    }

    LDAPMessage* res = nullptr;
    auto [attrArray, needsSecurityDescriptor] = prepareAttributeArray(attributes);
    
    LDAPControl sd_control;
    LDAPControl* server_ctrls[2] = {nullptr, nullptr};
    
    if (needsSecurityDescriptor) {
        setupSecurityDescriptorAttributes(sd_control, server_ctrls);
    }
    
    int returnCode = executeLdapSearch(
        baseDN, 
        scope, 
        query, 
        attrArray, 
        server_ctrls, 
        &res
    );
    
    LDAPResult results = processSearchResults(res);
    
    handleSearchError(returnCode, results);
    cleanupSearchResources(res);
    
    return results;
}

void LdapConnection::setupSecurityDescriptorAttributes(
    LDAPControl& sd_control,
    LDAPControl* server_ctrls[]
) {

    // Sequência BER codificada manualmente para o valor inteiro 7.
    // Estrutura: SEQUENCE (0x30) de tam 3, contendo INTEGER (0x02) de tam 1, com valor 0x07.
    // O valor 7 (OWNER|GROUP|DACL) instrui o servidor a retornar o Security Descriptor 
    // sem a SACL (informações de auditoria), o que requer privilégios elevados
    static char ber_val[] = { 0x30, 0x03, 0x02, 0x01, 0x07 };
    static struct berval bval = { 5, ber_val };
    sd_control.ldctl_oid = (char*)"1.2.840.113556.1.4.801";
    sd_control.ldctl_iscritical = 1;
    sd_control.ldctl_value = bval;
    server_ctrls[0] = &sd_control;
    server_ctrls[1] = NULL;
}

inline bool LdapConnection::isAuthenticated() const { 
    return isAuthenticated_; 
}

inline bool LdapConnection::isConnected() const { 
    return isConnected_; 
}

bool LdapConnection::initializeLdapSession(const std::string& host, unsigned short port) {
    std::string ldap_uri = buildLdapUri(host, port);
    
    int rc = ldap_initialize(&ldapSession, ldap_uri.c_str());
    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to initialize LDAP session: " << ldap_err2string(rc) << std::endl;
        ldapSession = nullptr;
        return false;
    }
    
    return true;
}

inline std::string LdapConnection::buildLdapUri(const std::string& host, unsigned short port) const {
    return "ldap://" + host + ":" + std::to_string(port);
}

bool LdapConnection::configureLdapOptions() {
    if (!setProtocolVersion()) {
        return false;
    }
    
    if (!setNetworkTimeout()) {
        std::cerr << "Warning: Could not set network timeout" << std::endl;
        // Não falha a conexão, apenas avisa
    }
    
    disableReferralChasing();
    return true;
}

bool LdapConnection::setProtocolVersion() {
    int ldapVersion = LDAP_VERSION3;
    int rc = ldap_set_option(ldapSession, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    
    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to set LDAP protocol version: " << ldap_err2string(rc) << std::endl;
        return false;
    }
    
    return true;
}

bool LdapConnection::setNetworkTimeout() {
    // Timeout de 30 segundos para operações de rede
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    
    int rc = ldap_set_option(ldapSession, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    return (rc == LDAP_SUCCESS);
}

inline void LdapConnection::disableReferralChasing() {
    int chase_referrals = 0;
    ldap_set_option(ldapSession, LDAP_OPT_REFERRALS, &chase_referrals);
}

inline void LdapConnection::cleanup() {
    if (ldapSession != nullptr) {
        ldap_unbind_ext_s(ldapSession, NULL, NULL);
        ldapSession = nullptr;
    }
}

inline struct berval LdapConnection::createCredentials(const std::string& password) const {
    struct berval creds;
    creds.bv_val = const_cast<char*>(password.c_str());
    creds.bv_len = password.length();
    return creds;
}

std::pair<std::vector<char*>, bool> LdapConnection::prepareAttributeArray(
const std::vector<std::string>& attributes
) const {
    std::vector<char*> attr;
    bool needsSecurityDescriptor = false;

    for (const auto& attribute : attributes) {
        attr.push_back(const_cast<char*>(attribute.c_str()));
        if (attribute == "nTSecurityDescriptor") {
            needsSecurityDescriptor = true;
        }
    }
    attr.push_back(NULL);
    
    return {attr, needsSecurityDescriptor};
}


int LdapConnection::executeLdapSearch(
    const std::string& baseDN,
    int scope,
    const std::string& query,
    const std::vector<char*>& attributes,
    LDAPControl** serverControls,
    LDAPMessage** result
) {
    disableReferralChasing();
    
    struct timeval search_timeout;
    search_timeout.tv_sec = 30;
    search_timeout.tv_usec = 0;
    
    return ldap_search_ext_s(
        ldapSession, 
        baseDN.c_str(), 
        scope,
        query.c_str(), 
        const_cast<char**>(attributes.data()), 
        0, 
        serverControls, 
        NULL, 
        &search_timeout,
        0, 
        result
    );
}


LDAPResult LdapConnection::processSearchResults(LDAPMessage* result) {
    LDAPResult results;
    
    // Validação adicional de segurança
    if (result == nullptr || ldapSession == nullptr) {
        return results;
    }

    for (LDAPMessage* entry = ldap_first_entry(ldapSession, result); 
         entry != nullptr; 
         entry = ldap_next_entry(ldapSession, entry)) 
    {
        auto entryData = processEntry(entry);
        results.push_back(entryData);
    }
    
    return results;
}

std::map<std::string, std::vector<std::string>> LdapConnection::processEntry(LDAPMessage* entry) {
    std::map<std::string, std::vector<std::string>> entryData;
    BerElement* ber = nullptr;
    
    for (char* attrName = ldap_first_attribute(ldapSession, entry, &ber);
         attrName != nullptr;
         attrName = ldap_next_attribute(ldapSession, entry, ber)) 
    {
        auto attrValues = extractAttributeValues(entry, attrName);
        entryData[attrName] = attrValues;
        ldap_memfree(attrName);
    }
    
    if (ber != nullptr) {
        ber_free(ber, 0);
    }
    
    return entryData;
}

std::vector<std::string> LdapConnection::extractAttributeValues(
    LDAPMessage* entry, 
    const char* attributeName) 
{
    std::vector<std::string> values;
    berval** rawValues = ldap_get_values_len(ldapSession, entry, attributeName);
    
    if (rawValues == nullptr) {
        return values;
    }
    
    for (int i = 0; rawValues[i] != nullptr; i++) {
        std::string encodedValue = encodeAttributeValue(rawValues[i]);
        values.push_back(encodedValue);
    }
    
    ldap_value_free_len(rawValues);
    return values;
}

inline std::string LdapConnection::encodeAttributeValue(berval* value) const {
    const char* data = value->bv_val;
    size_t length = value->bv_len;
    
    if (is_printable(data, length)) {
        return std::string(data, length);
    }
    
    return "::" + base64_encode(data, length);
}

inline void LdapConnection::handleSearchError(int returnCode, const LDAPResult& results) const {
    if (returnCode != LDAP_SUCCESS && results.empty()) {
        if (returnCode != LDAP_NO_SUCH_OBJECT) {
            std::cerr << "LDAP Search Error: " << ldap_err2string(returnCode) << std::endl;
        }
    }
}

inline void LdapConnection::cleanupSearchResources(LDAPMessage* result) const {
    if (result != nullptr) {
        ldap_msgfree(result);
    }
}