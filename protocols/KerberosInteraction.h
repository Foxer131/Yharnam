#pragma once
#include <krb5.h>
#include <memory>
#include <string>
#include <optional>

struct Krb5ContextDeleter {
    void operator()(krb5_context ctx) const noexcept {
        if (ctx) krb5_free_context(ctx);
    }
};

struct Krb5LibraryCredsDeleter {
    krb5_context ctx;
    void operator()(krb5_creds* ptr) const noexcept {
        if (ctx && ptr) krb5_free_creds(ctx, ptr);
    }
};

struct Krb5UserCredsDeleter {
    krb5_context ctx;
    void operator()(krb5_creds* ptr) const noexcept {
        if (ctx && ptr) {
            krb5_free_cred_contents(ctx, ptr);
            delete ptr;
        }
    }
};

struct Krb5PrincipalDeleter {
    krb5_context ctx;
    void operator()(krb5_principal ptr) const noexcept {
        if (ctx && ptr) krb5_free_principal(ctx, ptr);
    }
};

struct Krb5CcacheDeleter {
    krb5_context ctx;
    void operator()(krb5_ccache cache) const noexcept {
        if (ctx && cache) 
            krb5_cc_close(ctx, cache);
    }
};

class KerberosTicketFormatter {
public:
    static std::string formatTicket_TGS(krb5_context ctx, const krb5_creds& creds);
    static std::string formatTicket_TGT(krb5_context ctx, const krb5_creds& creds);

private:
    static std::string principal_to_string(krb5_context context, krb5_principal principal);
    static void split_principal(const std::string& full_principal, std::string& name, std::string& realm);

    struct CipherLocation {
        const unsigned char* start;
        size_t length;
        size_t offset;
    };
    
    static std::optional<CipherLocation> findCipherInTicket(
        const unsigned char* ticketData,
        size_t ticketLength
    );
    
    static std::optional<krb5_enctype> findEncryptionType(
        const unsigned char* ticketData,
        size_t cipherOffset
    );
    
    static size_t getChecksumSize(krb5_enctype etype);
    static const char* getEncryptionName(krb5_enctype etype);

    static std::string to_hex(const unsigned char* data, size_t len);
    
    static std::string buildTGSHash(
        const std::string& serverName,
        const std::string& serverRealm,
        krb5_enctype etype,
        const std::string& checksumHex,
        const std::string& encDataHex
    );
    
    static std::string buildASREPHash(
        const std::string& username,
        const std::string& realm,
        krb5_enctype etype,
        const std::string& checksumHex,
        const std::string& encDataHex
    );
};

class KerberosInteraction {
public:
    KerberosInteraction();
    
    krb5_context getContext() { return context_.get(); }
    
    bool requestAndCacheTGT(const std::string& username, const std::string& password);
    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> requestRawTGT(
        const std::string& username, 
        const std::string& password
    );
    bool cacheTicket(const krb5_creds& creds, const std::string& username);
    
    std::string requestAndFormatTGS(const std::string& spn, const std::string& user_requesting);

private:
    std::unique_ptr<std::remove_pointer_t<krb5_context>, Krb5ContextDeleter> context_;



    std::unique_ptr<krb5_principal_data, Krb5PrincipalDeleter> parsePrincipal(
        const std::string& principalName
    );

    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> obtainInitialCredentials(
        krb5_principal principal,
        const std::string& password
    );

    std::unique_ptr<_krb5_ccache, Krb5CcacheDeleter> openDefaultCache();
    
    bool initializeCache(krb5_ccache cache, krb5_principal principal);
    bool storeInCache(krb5_ccache cache, const krb5_creds& creds);

    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> prepareServiceRequest(
        krb5_principal userPrincipal,
        krb5_principal servicePrincipal
    );
    
    std::unique_ptr<krb5_creds, Krb5LibraryCredsDeleter> requestRawTGS(
        krb5_ccache cache,
        krb5_creds* requestTemplate
    );
};
