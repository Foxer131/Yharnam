#include <iostream>
#include "ArgumentParser.h"
#include <algorithm>
#include <sstream>

ArgumentParser::ArgumentParser() {}



void ArgumentParser::transformUserDomain() {
    if (user.username.find("@") != std::string::npos) {
        size_t at_pos = user.username.find("@");
        std::string transform = user.username.substr(at_pos + 1);
        std::transform(transform.begin(), transform.end(), transform.begin(), ::toupper);

        std::string _username = user.username.substr(0, at_pos);
        user.username = _username + "@" + transform;
        return;
    } else if (!DC.empty()) {
        std::transform(DC.begin(), DC.end(), DC.begin(), ::toupper);
        user.username += "@" + DC;
    }
}

std::string ArgumentParser::makeBaseDN() const {
    size_t pos = DC.find(".");
    std::string toplevel_DC = "", 
                domainname_DC = "";

    if (pos != std::string::npos) {
        toplevel_DC = "DC=" + DC.substr(pos + 1);
        domainname_DC = "DC=" + DC.substr(0, pos);
        
    } else if (( pos = user.username.find(".") ) != std::string::npos) {
        size_t at_pos = user.username.find("@");

        std::string only_domain = user.username.substr(at_pos + 1);
        size_t dot_after_at = only_domain.find(".");

        if (at_pos == std::string::npos)
            return "";
        toplevel_DC = "DC=" + only_domain.substr(dot_after_at + 1);
        domainname_DC = "DC=" + only_domain.substr(0, dot_after_at);
    }
    return domainname_DC + "," + toplevel_DC;    
}

void ArgumentParser::printHelp() {
    std::cerr << R"(
Yharnam LDAP Enumerator & Attack Vector Tool
Usage: Yharnam <target_ip> -u <username> -p <password> -dc <domain_controller> [OPTIONS]

Target & Authentication:
  <target_ip>            IP address of the target LDAP server (DC).
  -u, --username         Username for authentication (e.g., 'user' or 'user@domain.local').
  -p, --password         Password for authentication.
  -dc, --domain          The FQDN of the Domain Controller (e.g., yharnam.local).
                         Required for Kerberos ticket requests.

Attack Modules:
  --kerberoast           Perform Kerberoasting attack against SPN accounts.
                         Extracts TGS tickets for offline cracking.
  --asreproast           Perform AS-REP Roasting attack against users with
                         'Do not require Kerberos preauthentication' enabled.
  --find-acls [TARGETS]  Scan for dangerous ACLs (GenericWrite, WriteOwner, etc).
                         Optional: Provide comma-separated list of users/groups.
                         Default: Scans Admin groups (Domain Admins, etc).
                         Example: --find-acls "sql_svc,backup_adm"
  --find-acls all        Scan ACLs for ALL users in the domain (Noisy!).

Analysis & Forensics:
  --whoami               Enumerate current user privileges, groups and metadata.
  --query "<filter>"     Execute a custom LDAP query.
                         Example: --query "(objectClass=computer)\"
  --attrs "<list>"       Specify attributes to fetch for custom query (comma separated).
                         Default: Fetch all attributes.

Output:
  -outputfile <path>     Save attack artifacts (hashes) to a file.

Examples:
  ./Yharnam 10.10.10.5 -u "isabel.l" -p "Pass123" -dc yharnam.local --kerberoast -outputfile hashes.txt
  ./Yharnam 10.10.10.5 -u "isabel.l" -p "Pass123" -dc yharnam.local --find-acls
  ./Yharnam 10.10.10.5 -u "isabel.l" -p "Pass123" -dc yharnam.local --whoami
)" << std::endl;
}

constexpr unsigned int hash(std::string_view str) {
    unsigned int hash = 0;
    for (auto& c : str) {
        hash = hash*31 + c;
    }
    return hash;
} 

bool ArgumentParser::parse(int& argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return false;
    }

    ip = argv[1];

    for (int i = 1; i < argc; i++) {
        const unsigned int rule = hash(argv[i]);
        switch (rule) {
            case hash("-u"): {
                if (i + 1 < argc)
                    user.username = argv[++i];
                transformUserDomain();
                break;
            }
            case hash("-p"):
                if (i + 1 < argc)
                    user.password = argv[++i];
                break;
            case hash("-dc"): {
                if (i + 1 < argc) 
                    DC = argv[++i];
                    transformUserDomain();
                break;
            }
            case hash("--query"):
            case hash("-q") : {
                if (i + 1 < argc)
                    query = argv[++i];
                currentModule = QUERY;
                break;
            }
            case hash("--attrs"):
                if (i + 1 < argc) {
                    std::string rawAttrs = argv[++i];
                    std::stringstream ss(rawAttrs);
                    std::string segment;
                    // Split por vírgula
                    while(std::getline(ss, segment, ',')) {
                        customAttributes.push_back(segment);
                    }
                }
                break;
            case hash("--whoami"):
                currentModule = WHOAMI;
                break;
            case hash("--find-acls"): {
                currentModule = FINDACLS;
                if (i + 1< argc && std::string(argv[i+1]).rfind("-", 0) != 0) {
                    std::string alvo = argv[++i];
                    if (alvo == "all")
                        scanAll = true;
                    else {
                        std::stringstream ss(alvo);
                        std::string segment;
                        while(std::getline(ss, segment, ',')) {
                            segment.erase(0, segment.find_first_not_of(' '));
                            segment.erase(segment.find_last_not_of(' ') + 1);
                            if(!segment.empty()) 
                                customTargets.push_back(segment);
                    }
                    }
                } else {
                    scanAll = true;
                }
                break;
            }
            case hash("-h"):
                printHelp();
                return false;
            case hash("--kerberoast"):
                currentModule = KERBEROAST;
                break;
            case hash("--asreproast"):
                currentModule = ASREPROAST;
                break;
            case hash("-outputfile"):
                if (i + 1 < argc)
                    file_path = argv[++i];
                break;
        }
    }

    if (ip.empty() || user.username.empty() || user.password.empty()) {
        std::cerr << "\nError: Missing one or more required arguments." << std::endl;
        printHelp();
        return false;
    }

    return true;
}