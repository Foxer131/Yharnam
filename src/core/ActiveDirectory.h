#pragma once
#include <map>
#include <string>

// Active Directory domain knowledge shared across modules: SID/RID names,
// userAccountControl flags, and the magic constants used to build LDAP filters.
// Centralising these avoids re-encoding the same facts in every module and
// gives new modules (targeted Kerberoast, deeper ACL hunting, native AS-REP) a
// single source of truth.
namespace AD {

// LDAP "bitwise AND" matching rule OID, used as
// "userAccountControl:1.2.840.113556.1.4.803:=<flag>".
inline constexpr const char* MatchingRuleBitAnd = "1.2.840.113556.1.4.803";

// sAMAccountType values.
namespace SamAccountType {
inline constexpr const char* NormalUser = "805306368";
}

// userAccountControl bit flags.
namespace Uac {
inline constexpr int Disabled             = 0x00002;
inline constexpr int LockedOut            = 0x00010;
inline constexpr int PasswdNotRequired    = 0x00020;
inline constexpr int DontExpirePassword   = 0x10000;
inline constexpr int DontRequirePreauth   = 0x400000;
inline constexpr int TrustedForDelegation = 0x80000;
}

// Well-known SIDs referenced when filtering ACLs.
namespace Sid {
inline constexpr const char* Everyone           = "S-1-1-0";
inline constexpr const char* AuthenticatedUsers = "S-1-5-11";
inline constexpr const char* Self               = "S-1-5-10";
inline constexpr const char* System             = "S-1-5-18";
inline constexpr const char* CreatorOwner       = "S-1-3-0";
}

/// @brief Maps a primaryGroupID RID to its well-known group name.
/// @return The group name, or "RID-<rid>" if it is not a built-in group.
inline std::string primaryGroupName(const std::string& rid) {
    static const std::map<std::string, std::string> kRidNames = {
        {"512", "Domain Admins"},
        {"513", "Domain Users"},
        {"514", "Domain Guests"},
        {"515", "Domain Computers"},
        {"516", "Domain Controllers"},
        {"518", "Schema Admins"},
        {"519", "Enterprise Admins"},
        {"520", "Group Policy Creator Owners"},
    };

    auto it = kRidNames.find(rid);
    return it != kRidNames.end() ? it->second : "RID-" + rid;
}

/// @brief Resolves a SID string to a well-known principal name without a query.
/// @return The principal name, or an empty string if the SID is not well-known.
inline std::string wellKnownPrincipal(const std::string& sid) {
    if (sid == Sid::AuthenticatedUsers) return "Authenticated Users";
    if (sid == Sid::Everyone)           return "Everyone";
    // Domain/forest RID suffixes (the domain-specific prefix varies).
    if (sid.find("-512") != std::string::npos && sid.length() < 45) return "Domain Admins";
    if (sid.find("-519") != std::string::npos) return "Enterprise Admins";
    if (sid.find("-544") != std::string::npos) return "Administrators";
    return "";
}

/// @brief Whether a SID is a local/system principal that ACL scans should skip.
inline bool isSystemPrincipal(const std::string& sid) {
    return sid == Sid::System || sid == Sid::Self || sid == Sid::CreatorOwner;
}

/// @brief Whether a SID is a broad public group (Everyone / Authenticated Users).
inline bool isPublicPrincipal(const std::string& sid) {
    return sid == Sid::Everyone || sid == Sid::AuthenticatedUsers;
}

}  // namespace AD
