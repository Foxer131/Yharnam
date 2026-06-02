#pragma once
#include <string>
#include <vector>
#include <map>
#include <utility>
#include "LdapQuerier.h"

typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;
typedef struct ldapcontrol LDAPControl;
typedef struct berval berval;

/**
 * @class LdapConnection
 * @brief Manages an LDAP/Active Directory connection.
 *
 * Provides a small interface to connect, authenticate and search against
 * LDAP/Active Directory servers.
 *
 * Typical use:
 * @code
 *   LdapConnection ldap{"192.168.1.1", 389};
 *   if (ldap.connect()) {
 *       if (ldap.login("CN=user,DC=domain,DC=com", "password")) {
 *           auto results = ldap.executeQueryAndUnpackData(
 *               "DC=domain,DC=com",
 *               "(objectClass=user)",
 *               {"cn", "mail", "nTSecurityDescriptor"}
 *           );
 *       }
 *   }
 * @endcode
 */
class LdapConnection : public LdapQuerier{
public:
    LdapConnection(const std::string& host, size_t port = 389);
    ~LdapConnection();

    LdapConnection(const LdapConnection&) = delete;
    LdapConnection& operator=(const LdapConnection&) = delete;

    /**
     * @brief Initializes the LDAP session (does not contact the server yet).
     * @param host Server address (IP or hostname)
     * @param port LDAP port (default: 389, LDAPS: 636)
     * @return true on success
     */
    bool initialize(const std::string& host, size_t port = 389);

    /**
     * @brief Performs the anonymous root-DSE probe that establishes the session.
     * @return true once the server is reachable
     */
    bool connect();

    /**
     * @brief Closes the LDAP session.
     */
    void disconnect();

    /**
     * @brief Authenticates against the server (simple bind).
     * @param username Full user DN or UPN (e.g. "CN=user,DC=domain,DC=com")
     * @param password User password
     * @return true on successful authentication
     */
    bool login(const std::string& username, const std::string& password);

    /**
     * @brief BASE-scope search (the base object only).
     * @param baseDN Distinguished Name of the base object
     * @param query LDAP filter (e.g. "(objectClass=*)")
     * @param attributes Attributes to return
     * @return Search results
     */
    LDAPResult executeBaseScopeQueryAndUnpackData(
        const std::string& baseDN,
        const std::string& query,
        const std::vector<std::string>& attributes
    ) override;

    /**
     * @brief SUBTREE-scope search (the base object and all descendants).
     * @param baseDN Distinguished Name of the base object
     * @param query LDAP filter (e.g. "(objectClass=user)")
     * @param attributes Attributes to return
     * @return Search results
     */
    LDAPResult executeQueryAndUnpackData(
        const std::string& baseDN,
        const std::string& query,
        const std::vector<std::string>& attributes
    ) override;

    /**
     * @brief Search with an explicit scope.
     * @param baseDN Distinguished Name of the base object
     * @param scope LDAP scope (LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE)
     * @param query LDAP filter
     * @param attributes Attributes to return
     * @return Search results
     */
    LDAPResult performSpecifiedScopeSearch(
        const std::string& baseDN,
        int scope,
        const std::string& query,
        const std::vector<std::string>& attributes
    );

    /**
     * @brief Whether a successful bind has happened.
     */
    bool isAuthenticated() const;

    /**
     * @brief Whether the session is established.
     */
    bool isConnected() const;

private:
    LDAP* ldapSession;      
    bool isAuthenticated_;  
    bool isConnected_;     

    bool initializeLdapSession(const std::string& host, unsigned short port);
    std::string buildLdapUri(const std::string& host, unsigned short port) const;

    bool configureLdapOptions();
    
    bool setProtocolVersion();
    bool setNetworkTimeout();
    void disableReferralChasing();
    void setupSecurityDescriptorAttributes(
        LDAPControl& sd_control,
        LDAPControl* server_ctrls[]
    );

    void cleanup();

    struct berval createCredentials(const std::string& password) const;

    std::pair<std::vector<char*>, bool> prepareAttributeArray(
        const std::vector<std::string>& attributes
    ) const;

    int executeLdapSearch(
        const std::string& baseDN,
        int scope,
        const std::string& query,
        const std::vector<char*>& attributes,
        LDAPControl** serverControls,
        LDAPMessage** result
    );

    void handleSearchError(int returnCode, const LDAPResult& results) const;
    void cleanupSearchResources(LDAPMessage* result) const;
};