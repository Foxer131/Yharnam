# AES (etype 17/18) AS-REP Hash Formatting — Design

**Date:** 2026-06-02
**Branch:** `feature/aes-asrep` (off `feature/module-expansion`)
**Roadmap item:** "AES (etype 17/18) AS-REP hash formatting — verify byte layout vs hashcat"

## Goal

Extend AS-REP roasting to emit crackable hashes for AES-keyed accounts
(etype 17 = AES128-CTS-HMAC-SHA1-96, etype 18 = AES256-CTS-HMAC-SHA1-96), not
just RC4 (etype 23). The RC4 path stays byte-for-byte unchanged.

## Background: verified hash layouts

Standard **hashcat has no AES AS-REP mode** (modes 18200 = RC4 only). The target
cracker for AES is **John the Ripper Jumbo** (`john --format=krb5asrep`, which
auto-detects etype 17/18/23). Verified against the JtR source
`src/krb5_asrep_fmt_plug.c` and its `tests[]` vectors.

| Field          | RC4 (etype 23)                              | AES (etype 17/18)                                   |
|----------------|---------------------------------------------|-----------------------------------------------------|
| Format string  | `$krb5asrep$23$user@REALM:<checksum>$<edata>`| `$krb5asrep$<etype>$<salt>$<edata2>$<checksum>`     |
| Checksum size  | 16 bytes (MD5-HMAC)                          | 12 bytes (HMAC-SHA1-96)                             |
| Checksum pos   | **head** of cipher                          | **tail** of cipher                                  |
| Salt field     | none (principal carries `user@REALM`)       | `UPPER(REALM) + username` concatenated, no separator|
| Cracker        | `hashcat -m 18200` (or JtR)                 | `john --format=krb5asrep` (hashcat unsupported)    |

Verbatim JtR etype-18 test vector (trailing 24 hex = 12-byte checksum):

```
$krb5asrep$18$EXAMPLE.COMluser$<edata2_hex>...$420973360c2e907b9053f1db
```

So for AES: `checksum = cipher[len-12 .. len]`, `edata2 = cipher[0 .. len-12]`,
`salt = upper(realm) + username`.

## Scope

Offer AES + RC4 in the AS-REQ etype list; the KDC returns the strongest key the
account holds; Yharnam formats per the returned etype. No new CLI flag.

## Changes

### 1. `KerberosInteraction::requestAndFormatASREP` (`src/protocols/KerberosInteraction.cpp:254`)

Replace the RC4-only etype list with a preference-ordered list:

```cpp
krb5_enctype etypes[] = {
    ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_ARCFOUR_HMAC,
};
krb5_get_init_creds_opt_set_etype_list(options, etypes, 3);
```

Update the comment: no longer RC4-only; AES does not require
`allow_weak_crypto`. Everything downstream (`parseAsRep`, `isSupportedEnctype`)
already accepts AES128/256.

### 2. `KerberosTicketFormatter::formatASREP` (`:681`)

Branch on `etype`:

- **RC4 (23):** unchanged — head 16-byte checksum, `buildASREPHash`.
- **AES (17/18):**
  - `checksumSize = getChecksumSize(etype)` → 12 (already correct).
  - `checksumHex = to_hex(cipher + cipherLen - 12, 12)`  (tail).
  - `edata2Hex   = to_hex(cipher, cipherLen - 12)`        (head).
  - `salt = upper(realm) + username`.
  - emit via new `buildASREPHashAES`.
- Guard `cipherLen >= checksumSize` (already present).

### 3. New `KerberosTicketFormatter::buildASREPHashAES(salt, etype, edata2Hex, checksumHex)`

Emits `$krb5asrep$<etype>$<salt>$<edata2>$<checksum>`. Existing RC4
`buildASREPHash` stays as-is. Add both declarations to the header
(`src/protocols/KerberosInteraction.h:92`).

### 4. Etype-aware cracker hint (`src/modules/attacks/ASREPRoast.cpp:94 run()`)

The hard-coded `hashcat -m 18200` line (`:121`) becomes etype-aware. The etype
is encoded in the hash string prefix, so no new plumbing through return types:

- collect all produced hashes in one vector (works for both stdout and file
  paths — minor `run()` tweak so hashes are available for the scan),
- if any hash starts `$krb5asrep$23$` → print `hashcat -m 18200 <hashfile> <wordlist>`,
- if any hash starts `$krb5asrep$17$` or `$krb5asrep$18$` → print
  `john --format=krb5asrep <hashfile> <wordlist>` (note: hashcat has no AES AS-REP mode),
- print both lines if both etypes appeared.

### 5. Header doc (`src/protocols/KerberosInteraction.h:52` and `:119`)

Update `formatASREP` / `requestAndFormatASREP` comments: no longer 18200-only;
describe RC4→hashcat and AES→JtR.

## Error handling

Unchanged. KRB-ERROR (pre-auth required / unknown account) and the
"unsupported/truncated cipher" branches already cover the failure paths. An
etype outside `isSupportedEnctype` falls through to the existing error.

## Testing

No unit-test suite exists. Verification:

1. **Build clean** under `-Wall -Wextra` (project invariant).
2. **Structural check vs JtR vector:** an AES hash string has exactly 5
   `$`-delimited fields, salt == `UPPER(REALM)+username`, final field == 24 hex
   (12 bytes).
3. **Live (if lab KDC available):** harvest a real AES AS-REP from a
   pre-auth-disabled, AES-keyed account; confirm `john --format=krb5asrep`
   accepts and (with a known password in a wordlist) cracks it. If no KDC is
   reachable in this environment, this step is flagged as unverified rather than
   claimed.

## Known caveat (documented, not fixed)

The AES salt assumes the AD default (`UPPER_REALM + sAMAccountName`). Accounts
with an explicit/custom Kerberos salt will produce a hash JtR cannot crack.
Noted in a code comment and in the CLAUDE.md gotchas.

## Out of scope

- New CLI flags.
- AES TGS-REP (`formatTicket_TGS`) — only AS-REP here.
- Reading the real salt from the KDC reply's PA-ETYPE-INFO2 (future improvement
  if custom-salt accounts become a need).
