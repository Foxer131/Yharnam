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

struct Krb5CredsDeleter {
    krb5_context ctx;
    void operator()(krb5_creds* ptr) const noexcept {
        if (ctx && ptr)
            krb5_free_cred_contents(ctx, ptr);
    }
};

struct Krb5PrincipalDeleter {
    krb5_context ctx;
    void operator()(krb5_principal ptr) const noexcept {
        if (ctx && ptr) krb5_free_principal(ctx, ptr);
    }
};

struct Krb5CloseCcache {
    krb5_context ctx;
    void operator()(krb5_ccache cache) {
        if (cache) 
            krb5_cc_close(ctx, cache);
    }
};

class KerberosInteraction {
private:
    std::unique_ptr<std::remove_pointer_t<krb5_context>, Krb5ContextDeleter> context_;

public:
    KerberosInteraction();

    krb5_context getContext() { return context_.get(); }
    bool requestTGT(const std::string& username, const std::string& password);
    std::string requestTGS(const std::string& spn, const std::string& user_requesting);


    std::optional<krb5_creds> requestTGTCreds(const std::string& username, const std::string& password);
    bool cacheTicket(const krb5_creds& creds, const std::string& username);

    class ASN1Parser {
        std::string principal_to_string(krb5_context context, krb5_principal principal) const;
        void split_principal(const std::string& full_principal, std::string& name, std::string& realm) const;
        std::string to_hex(const unsigned char* data, size_t len) const;
    public:
        std::string formatTicket_TGS(krb5_context ctx, const krb5_creds& creds);
        std::string formatTicket_TGT(krb5_context ctx, const krb5_creds& creds);
    };
};