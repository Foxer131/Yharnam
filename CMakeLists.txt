cmake_minimum_required(VERSION 3.12)
project(Yharnam VERSION 1.0 LANGUAGES CXX C)

# --- Compiler configuration ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEFAULT_SOURCE")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# --- Sources ---
set(YHARNAM_SOURCES
    src/main.cpp
    src/cli/ArgumentParser.cpp
    src/core/ModuleGenerator.cpp
    src/protocols/LdapConnection.cpp
    src/protocols/KerberosInteraction.cpp
    src/protocols/AclService.cpp
    src/modules/attacks/Kerberoast.cpp
    src/modules/attacks/ASREPRoast.cpp
    src/modules/analysis/Query.cpp
    src/modules/analysis/Whoami.cpp
    src/modules/analysis/FindAcls.cpp
    src/utils/Encoding.cpp
    src/utils/Utils.cpp
)

# --- Dependencies ---
find_package(PkgConfig REQUIRED)

# OpenLDAP, Samba NDR/Talloc and MIT Kerberos are all shipped with
# pkg-config files on every mainstream distro (Arch, Debian/Kali, Fedora).
# We rely on pkg-config first and only fall back to a manual search when a
# module is missing, so the build stays portable across layouts.
pkg_check_modules(LDAP REQUIRED ldap)
pkg_check_modules(KRB5 REQUIRED krb5)
pkg_check_modules(NDR ndr)
pkg_check_modules(TALLOC talloc)

# Manual fallback for NDR (older Samba packages without a .pc file).
if (NOT NDR_FOUND)
    message(STATUS "NDR not found via pkg-config, trying manual search...")
    find_path(NDR_INCLUDE_DIRS
        NAMES gen_ndr/ndr_svcctl.h ndr.h
        PATH_SUFFIXES samba-4.0 samba-4
    )
    find_library(NDR_LIBRARIES NAMES ndr libndr)
    if (NOT (NDR_INCLUDE_DIRS AND NDR_LIBRARIES))
        message(FATAL_ERROR "Could NOT find the NDR library. Install the Samba development package (e.g. samba-dev / smbclient).")
    endif()
endif()

# Manual fallback for Talloc.
if (NOT TALLOC_FOUND)
    message(STATUS "Talloc not found via pkg-config, trying manual search...")
    find_path(TALLOC_INCLUDE_DIRS NAMES talloc.h)
    find_library(TALLOC_LIBRARIES NAMES talloc libtalloc)
    if (NOT (TALLOC_INCLUDE_DIRS AND TALLOC_LIBRARIES))
        message(FATAL_ERROR "Could NOT find the Talloc library. Install libtalloc-dev.")
    endif()
endif()

# Samba ships the security-descriptor parser in a "private" shared object whose
# name and location differ per distro. Search the common Samba lib directories.
find_library(SAMBA_SEC_LIB
    NAMES
        samba-security-private-samba
        samba-security
    PATH_SUFFIXES samba
)
if (NOT SAMBA_SEC_LIB)
    message(FATAL_ERROR "Could NOT find libsamba-security-private-samba. Install the Samba libraries (samba-libs / samba).")
endif()
message(STATUS "Found samba-security: ${SAMBA_SEC_LIB}")

find_library(NDR_STD_LIB NAMES ndr-standard)
find_library(K5CRYPTO_LIB NAMES k5crypto)
find_library(COM_ERR_LIB NAMES com_err)

# --- Executable ---
add_executable(Yharnam ${YHARNAM_SOURCES})

target_compile_options(Yharnam PRIVATE -Wall -Wextra)

target_include_directories(Yharnam PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LDAP_INCLUDE_DIRS}
    ${KRB5_INCLUDE_DIRS}
    ${NDR_INCLUDE_DIRS}
    ${TALLOC_INCLUDE_DIRS}
)

target_link_libraries(Yharnam PRIVATE
    ${LDAP_LIBRARIES}
    ${KRB5_LIBRARIES}
    ${NDR_LIBRARIES}
    ${TALLOC_LIBRARIES}
    ${SAMBA_SEC_LIB}
)

# These libraries are dependencies of the ones above; link them when present.
foreach(extra_lib ${NDR_STD_LIB} ${K5CRYPTO_LIB} ${COM_ERR_LIB})
    target_link_libraries(Yharnam PRIVATE ${extra_lib})
endforeach()
