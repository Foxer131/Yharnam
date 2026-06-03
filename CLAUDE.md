# CLAUDE.md

Guidance for AI coding agents (and humans) working in this repository.

## What Yharnam is

Offensive LDAP / Active Directory enumeration and attack tool, written in
C++17. It authenticates to a Domain Controller over LDAP and runs one module:
Kerberoast, AS-REP Roast, ACL hunting (`find-acls`), a custom LDAP `query`, or
`whoami`. For authorized security testing and lab use only.

## Build & run

```sh
cmake -S . -B build          # configure (resolves deps via pkg-config)
cmake --build build -j       # build -> ./build/Yharnam
./build/Yharnam              # no args -> help
```

There is no test suite. **Verify changes by building clean and smoke-testing**:

```sh
cmake --build build -j 2>&1 | grep -iE 'warning|error' || echo clean
./build/Yharnam 127.0.0.1 -u u -p p -dc test.local --whoami   # graceful fail vs dead host
```

The build is warning-clean under `-Wall -Wextra`; keep it that way.

### Dependencies (Arch)

`sudo pacman -S --needed base-devel cmake openldap krb5 samba`. The Samba
security-descriptor parser lives at `/usr/lib/samba/libsamba-security-private-samba.so`;
CMake finds it with `PATH_SUFFIXES samba`. Debian/Fedora package names are in
`README.md`.

## Architecture (where things live)

```
src/
  main.cpp            Wires CLI -> connect -> login -> module->run()
  cli/                ArgumentParser: flags -> Modules enum + option fields
  core/
    Module.h          Abstract module interface (getName, run(ctx))
    Context.h         ModuleFactoryContext (build-time) / ModuleRuntimeContext (run-time)
    ModuleRegistry    Modules id -> factory; modules self-register
    ModuleGenerator   ModuleFactory facade over the registry
    ActiveDirectory.h Single source of AD constants (SIDs, RIDs, UAC, OIDs)
  protocols/
    LdapConnection    Session/auth/search (implements LdapQuerier)
    LdapResultParser  LDAPMessage* -> attribute/value maps
    KerberosInteraction  krb5: TGT/TGS/AS-REP + KerberosTicketFormatter
    KdcClient         Kerberos-over-TCP transport (port 88)
    AclService        nTSecurityDescriptor (Samba NDR) -> ACE list
  modules/
    attacks/          Kerberoast, ASREPRoast
    analysis/         Query, Whoami, FindAcls
  utils/              Colors, Encoding (base64), Utils (file), StringUtils
```

Data flow: `main` builds a `ModuleFactoryContext`, `ModuleFactory::createModule`
returns the `Module`, then `module->run(ModuleRuntimeContext)`. LDAP results are
`std::vector<std::map<std::string, std::vector<std::string>>>` (`LDAPResult`).

## Conventions (match these)

- Includes are **`src/`-root-relative**: `#include "core/Module.h"`, never
  `../../`. `src/` is the include root (set in CMake).
- Constructor parameters use a **trailing underscore** (`ldap_`), members are
  unadorned (`ldap`).
- Comments and docs in **English**.
- Centralize AD facts in `core/ActiveDirectory.h`; don't re-encode SID/RID/UAC
  literals in modules.
- Colours via `Colors::COLOR_*`; base64 via `Encoding::`.

## Adding a module (self-registration — factory needs no edit)

1. Declare the class in `modules/attacks/Attacks.h` or
   `modules/analysis/Analysis.h` (derive `Module`, implement `getName` + `run`).
2. Implement in a new `.cpp` under `modules/` and self-register:
   ```cpp
   #include "core/ModuleRegistry.h"
   namespace {
   const ModuleRegistry::Registrar registrar(
       Modules::MY_MODULE,
       [](const ModuleFactoryContext& ctx) -> std::unique_ptr<Module> {
           return std::make_unique<MyModule>(ctx.ldapService /*, ... */);
       });
   }  // namespace
   ```
3. Add the enum value in `cli/ArgumentParser.h` and parse its flag in
   `ArgumentParser::parse`.
4. Add the `.cpp` to `YHARNAM_SOURCES` in `CMakeLists.txt`.

If a module needs new run-time input, add a field to `ModuleRuntimeContext`
(stored **by value** — accessors return temporaries) and populate it in `main`.

## Gotchas

- **Editor diagnostics lie**: clang intellisense (`.vscode`) doesn't know `-Isrc`
  and reports "`core/Module.h` not found". The CMake build is the source of
  truth. Ignore those; trust `cmake --build`.
- **AS-REP roast etypes**: `requestAndFormatASREP` offers AES256/AES128/RC4 in
  the AS-REQ; the KDC returns the strongest key the account holds. AES (17/18)
  hashes crack with `john --format=krb5asrep` (hashcat has no AES AS-REP mode);
  RC4 (23) with `hashcat -m 18200` (RC4 needs an RC4 key on the account and
  `allow_weak_crypto = true` under `[libdefaults]` in `/etc/krb5.conf`). The AES
  salt is assumed to be the AD default `UPPER(REALM)+sAMAccountName`; accounts
  with a custom Kerberos salt produce a hash JtR cannot crack.
- **Kerberos transport is manual**: we build the AS-REQ with
  `krb5_init_creds_step` but do our own TCP to the DC (`KdcClient`), so no
  `krb5.conf` realm/KDC mapping is required.
- **Samba headers are C**: `AclService.cpp` includes them under `extern "C"`.

## Git / reversibility

- Default branch: `main`. Active feature work: `feature/module-expansion`.
- Structural refactors were merged with `--no-ff`; the pre-refactor state is
  tagged `pre-structure-pass-2` (revert a merge with `git revert -m 1 <sha>`).
- Branch before committing to `main`. Commit only when asked. Commit trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Roadmap (feature/module-expansion)

- [x] Native AS-REP roast (replaced impacket `system()` call)
- [x] AES (etype 17/18) AS-REP hash formatting (crack with `john --format=krb5asrep`)
- [ ] Targeted Kerberoast: `--kerberoast <user>` for a single SPN
- [ ] Deeper ACL search: parse `ACCESS_ALLOWED_OBJECT` ObjectType GUIDs
      (User-Force-Change-Password, Self-Membership, write-to-property)
