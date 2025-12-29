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
 * @brief Classe para gerenciamento de conexões LDAP/AD
 * 
 * Esta classe fornece uma interface limpa para conectar, autenticar e 
 * realizar buscas em servidores LDAP/Active Directory.
 * 
 * Uso típico:
 * @code
 *   LdapConnection ldap;
 *   if (ldap.initialize("192.168.1.1", 389)) {
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
    LdapConnection();
    ~LdapConnection();

    LdapConnection(const LdapConnection&) = delete;
    LdapConnection& operator=(const LdapConnection&) = delete;

    /**
     * @brief Conecta ao servidor LDAP
     * @param host Endereço do servidor (IP ou hostname)
     * @param port Porta LDAP (padrão: 389, LDAPS: 636)
     * @return true se conectado com sucesso
     */
    bool initialize(const std::string& host, unsigned short port = 389);

    bool connect();
    
    /**
     * @brief Desconecta do servidor LDAP
     */
    void disconnect();
    
    /**
     * @brief Autentica no servidor LDAP
     * @param username DN completo do usuário (ex: "CN=user,DC=domain,DC=com")
     * @param password Senha do usuário
     * @return true se autenticado com sucesso
     */
    bool login(const std::string& username, const std::string& password);

    /**
     * @brief Executa busca com escopo BASE (apenas o objeto especificado)
     * @param baseDN Distinguished Name do objeto base
     * @param query Filtro LDAP (ex: "(objectClass=*)")
     * @param attributes Lista de atributos a retornar
     * @return Resultados da busca
     */
    LDAPResult executeBaseScopeQueryAndUnpackData(
        const std::string& baseDN, 
        const std::string& query, 
        const std::vector<std::string>& attributes
    ) override;

    /**
     * @brief Executa busca com escopo SUBTREE (objeto e todos descendentes)
     * @param baseDN Distinguished Name do objeto base
     * @param query Filtro LDAP (ex: "(objectClass=user)")
     * @param attributes Lista de atributos a retornar
     * @return Resultados da busca
     */
    LDAPResult executeQueryAndUnpackData(
        const std::string& baseDN, 
        const std::string& query, 
        const std::vector<std::string>& attributes
    ) override;

    /**
     * @brief Executa busca com escopo especificado
     * @param baseDN Distinguished Name do objeto base
     * @param scope Escopo LDAP (LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE)
     * @param query Filtro LDAP
     * @param attributes Lista de atributos a retornar
     * @return Resultados da busca
     */
    LDAPResult performSpecifiedScopeSearch(
        const std::string& baseDN, 
        int scope, 
        const std::string& query, 
        const std::vector<std::string>& attributes
    );

    /**
     * @brief Verifica se está autenticado
     * @return true se autenticado
     */
    bool isAuthenticated() const;
    
    /**
     * @brief Verifica se está conectado
     * @return true se conectado
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

    LDAPResult processSearchResults(LDAPMessage* result);
    SingleLDAPResult processEntry(LDAPMessage* entry);
    std::vector<std::string> extractAttributeValues(LDAPMessage* entry, const char* attributeName);
    std::string encodeAttributeValue(berval* value) const;


    void handleSearchError(int returnCode, const LDAPResult& results) const;
    void cleanupSearchResources(LDAPMessage* result) const;
};