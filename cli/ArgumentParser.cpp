#include <iostream>
#include "ArgumentParser.h"
#include "../attacks/Attacks.h"

ArgumentParser::ArgumentParser() {}


User ArgumentParser::getUser() const { return user; }
std::string ArgumentParser::getDC() const { return DC; }
std::string ArgumentParser::getIP() const { return ip; }
AttackMethod ArgumentParser::getAttackMethod() const { return attackMethod; }
std::string ArgumentParser::getFilePath() const { return file_path; }

void ArgumentParser::printHelp() {
    std::cerr << "Yharnam LDAP Enumerator" << std::endl;
    std::cerr << "Usage: Yharnam <target_ip> -u <username> -p <password> -dc <domain_controller>" << std::endl;
    std::cerr << "\nRequired Arguments:" << std::endl;
    std::cerr << "  <target_ip>        IP address of the target LDAP server." << std::endl;
    std::cerr << "  -u, --username     Username for authentication (e.g., 'domain\\user')." << std::endl;
    std::cerr << "  -p, --password     Password for authentication." << std::endl;
    std::cerr << "  -dc, --domain      The domain controller path (eg: yharnam.local)." << std::endl;
    std::cerr << "  -outputfile        Output file containing hashes captured" << std::endl;
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
            case hash("-u"):
                if (i + 1 < argc)
                    user.username = argv[++i];
                break;
            case hash("-p"):
                if (i + 1 < argc)
                    user.password = argv[++i];
                break;
            case hash("-dc"):
                if (i + 1 < argc) 
                    DC = argv[++i];
                break;
            case hash("-h"):
                printHelp();
                return false;
            case hash("--kerberoast"):
                attackMethod = KERBEROAST;
                break;
            case hash("--asreproast"):
                attackMethod = ASREPROAST;
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