# Yharnam

Offensive LDAP / Active Directory enumeration and attack tool. Yharnam
authenticates against a Domain Controller over LDAP and runs one of several
modules: Kerberoasting, AS-REP Roasting, ACL hunting, custom LDAP queries, and
a `whoami` privilege dump.

> For authorized security testing and lab use only.

Contributing (or using an AI agent on this repo)? Read **[CLAUDE.md](CLAUDE.md)**
for the architecture map, conventions, and gotchas.

## Features

| Module        | Flag             | Description                                                    |
|---------------|------------------|----------------------------------------------------------------|
| Kerberoast    | `--kerberoast`   | Requests TGS tickets for SPN accounts (hashcat `-m 13100`).    |
| AS-REP Roast  | `--asreproast`   | Targets accounts without Kerberos pre-auth (hashcat `-m 18200`).|
| Find ACLs     | `--find-acls`    | Hunts dangerous DACL rights (GenericWrite, WriteOwner, ...).    |
| Whoami        | `--whoami`       | Dumps the current user's metadata, groups and UAC flags.       |
| Query         | `--query "<f>"`  | Runs an arbitrary LDAP filter; `--attrs` selects attributes.   |

## Dependencies

- A C++17 compiler (GCC or Clang) and CMake >= 3.12
- OpenLDAP (`libldap`)
- MIT Kerberos (`krb5`)
- Samba libraries: NDR, Talloc and the `samba-security` security-descriptor parser

Install them with your distribution's package manager:

```sh
# Arch Linux
sudo pacman -S --needed base-devel cmake openldap krb5 samba

# Debian / Kali / Ubuntu
sudo apt install build-essential cmake libldap2-dev libkrb5-dev \
                 libsamba-dev libndr-dev libtalloc-dev samba-libs

# Fedora
sudo dnf install gcc-c++ cmake openldap-devel krb5-devel libtalloc-devel samba-devel
```

The build resolves OpenLDAP, Kerberos, NDR and Talloc through `pkg-config`, so
it is portable across distributions and does not hard-code library paths.

## Building

```sh
cmake -S . -B build
cmake --build build -j
# binary: ./build/Yharnam
```

## Usage

```sh
Yharnam <target_ip> -u <username> -p <password> -dc <domain.fqdn> [module] [options]
```

Examples:

```sh
./build/Yharnam 10.10.10.5 -u 'isabel.l' -p 'Pass123' -dc yharnam.local --kerberoast -outputfile hashes.txt
./build/Yharnam 10.10.10.5 -u 'isabel.l' -p 'Pass123' -dc yharnam.local --find-acls
./build/Yharnam 10.10.10.5 -u 'isabel.l' -p 'Pass123' -dc yharnam.local --query '(objectClass=computer)'
```

Run with no arguments (or `-h`) for the full help text.

## AS-REP roasting notes

`--asreproast` is fully native (no `impacket`): Yharnam sends a no-pre-auth
AS-REQ to the DC on TCP/88 and harvests the AS-REP, producing a
`hashcat -m 18200` hash. Two requirements:

- The target account must have an **RC4** Kerberos key.
- The local MIT krb5 must permit RC4. Add to `/etc/krb5.conf`:
  ```ini
  [libdefaults]
      allow_weak_crypto = true
  ```

Crack with: `hashcat -m 18200 hashes.txt wordlist.txt`.

AES (etype 17/18) AS-REP output is a planned follow-up.

## Architecture

A one-screen map of the codebase, the module data flow, and the project
conventions lives in **[CLAUDE.md](CLAUDE.md)**. In short: `main` wires
`CLI -> connect -> login -> module.run()`; modules implement the `Module`
interface and **self-register** with `ModuleRegistry`; protocol services
(`LdapConnection`, `KerberosInteraction`, `KdcClient`, `AclService`) are split
by responsibility; AD constants live in `core/ActiveDirectory.h`.

## Project layout

```
src/
  main.cpp              Program entry point / wiring
  cli/                  Command-line parsing (ArgumentParser)
  core/                 Module interface, factory and shared context structs
  protocols/            LDAP, Kerberos and ACL/security-descriptor services
  modules/
    attacks/            Kerberoast, ASREPRoast
    analysis/           Query, Whoami, FindAcls
  utils/                Colours, Base64/encoding, file helpers, string helpers
```

All headers are included by their `src/`-relative path (e.g.
`#include "core/Module.h"`), so files can be moved without rewriting `../../`
include chains.

## Adding a new module

Modules self-register, so the factory never needs editing:

1. Declare the class in the relevant header (`modules/attacks/Attacks.h` or
   `modules/analysis/Analysis.h`), deriving from `Module` and implementing
   `getName()` and `run(const ModuleRuntimeContext&)`.
2. Implement it in a new `.cpp` under `modules/`, and register it there:
   ```cpp
   #include "core/ModuleRegistry.h"
   namespace {
   const ModuleRegistry::Registrar registrar(
       Modules::MY_MODULE,
       [](const ModuleFactoryContext& ctx) -> std::unique_ptr<Module> {
           return std::make_unique<MyModule>(ctx.ldapService /* , ... */);
       });
   }  // namespace
   ```
3. Add a value to the `Modules` enum in `cli/ArgumentParser.h` and parse its
   flag in `ArgumentParser::parse`.
4. Add the new source file to `YHARNAM_SOURCES` in `CMakeLists.txt`.
