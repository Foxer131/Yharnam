cmake_minimum_required(VERSION 3.12)
project(Yharnam VERSION 1.0 LANGUAGES CXX C)

# --- Configurações do Compilador ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "-D_DEFAULT_SOURCE")

# --- Definição das Fontes ---
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
    src/utils/Utils.cpp
    src/utils/Colors.cpp
)

# --- Dependências ---

find_package(PkgConfig REQUIRED)

# 1. OpenLDAP
pkg_check_modules(LDAP REQUIRED ldap)

# 2. Samba / NDR / Talloc
pkg_check_modules(NDR ndr)
pkg_check_modules(TALLOC talloc)

# Fallback Manual para NDR
if (NOT NDR_FOUND)
    message(STATUS "NDR not found via pkg-config, trying manual search...")
    find_path(NDR_INCLUDE_DIRS 
        NAMES gen_ndr/ndr_svcctl.h ndr.h
        PATHS /usr/include/samba-4.0 /usr/include/samba-4 /usr/include
        PATH_SUFFIXES samba-4.0 samba-4
    )
    find_library(NDR_LIBRARIES 
        NAMES ndr libndr
        PATHS /usr/lib/x86_64-linux-gnu /usr/lib
    )
    if (NDR_INCLUDE_DIRS AND NDR_LIBRARIES)
        set(NDR_FOUND TRUE)
        message(STATUS "Found NDR manually: ${NDR_LIBRARIES}")
    else()
        message(FATAL_ERROR "Could NOT find NDR library. Install samba-dev")
    endif()
endif()

# Fallback Manual para Talloc
if (NOT TALLOC_FOUND)
    message(STATUS "Talloc not found via pkg-config, trying manual search...")
    find_path(TALLOC_INCLUDE_DIRS NAMES talloc.h PATHS /usr/include)
    find_library(TALLOC_LIBRARIES NAMES talloc libtalloc PATHS /usr/lib/x86_64-linux-gnu /usr/lib)
    if (TALLOC_INCLUDE_DIRS AND TALLOC_LIBRARIES)
        set(TALLOC_FOUND TRUE)
    else()
        message(FATAL_ERROR "Could NOT find Talloc library. Install libtalloc-dev")
    endif()
endif()

# 3. Busca de Libs Adicionais do Samba (CORRIGIDO COM O NOME REAL)
find_library(SAMBA_SEC_LIB 
    NAMES 
        samba-security-private-samba      # O nome exato encontrado no seu Kali
        libsamba-security-private-samba   # Variação com prefixo lib
        samba-security                    # Fallback genérico
        libsamba-security
    PATHS 
        /usr/lib/x86_64-linux-gnu/samba 
        /usr/lib/samba 
        /usr/lib64/samba
    NO_DEFAULT_PATH
)

# Fallback nos caminhos padrão
if (NOT SAMBA_SEC_LIB)
    find_library(SAMBA_SEC_LIB NAMES samba-security-private-samba samba-security)
endif()

find_library(NDR_STD_LIB NAMES ndr-standard)

# Setup da lista de bibliotecas extras
set(SAMBA_EXTRA_LIBS "")

if (SAMBA_SEC_LIB)
    message(STATUS "Found samba-security: ${SAMBA_SEC_LIB}")
    list(APPEND SAMBA_EXTRA_LIBS ${SAMBA_SEC_LIB})
else()
    message(FATAL_ERROR "Could NOT find libsamba-security-private-samba.so! Verifique sua instalação do samba-libs.")
endif()

if (NDR_STD_LIB)
    message(STATUS "Found ndr-standard: ${NDR_STD_LIB}")
    list(APPEND SAMBA_EXTRA_LIBS ${NDR_STD_LIB})
endif()

# 4. MIT Kerberos
find_library(KRB5_LIB krb5 PATHS /usr/lib/x86_64-linux-gnu/mit-krb5 NO_DEFAULT_PATH REQUIRED)
find_library(K5CRYPTO_LIB k5crypto PATHS /usr/lib/x86_64-linux-gnu/mit-krb5 NO_DEFAULT_PATH REQUIRED)
find_library(COM_ERR_LIB com_err PATHS /usr/lib/x86_64-linux-gnu REQUIRED)
find_path(KRB5_INCLUDE krb5.h PATHS /usr/include/mit-krb5 PATH_SUFFIXES krb5 REQUIRED)

# --- Criação do Executável ---

add_executable(Yharnam ${YHARNAM_SOURCES})

# --- Includes ---
target_include_directories(Yharnam PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LDAP_INCLUDE_DIRS}
    ${KRB5_INCLUDE}
    ${NDR_INCLUDE_DIRS}
    ${TALLOC_INCLUDE_DIRS}
)

# --- Linkagem ---
target_link_libraries(Yharnam PRIVATE
    ${LDAP_LIBRARIES}
    ${KRB5_LIB}
    ${K5CRYPTO_LIB}
    ${COM_ERR_LIB}
    ${NDR_LIBRARIES}
    ${TALLOC_LIBRARIES}
    ${SAMBA_EXTRA_LIBS}
)