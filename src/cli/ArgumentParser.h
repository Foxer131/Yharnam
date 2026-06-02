#pragma once

#include <string>
#include <vector>

struct User {
    std::string password;
    std::string username;
};

enum class Modules {
    KERBEROAST,
    ASREPROAST,
    GOLDEN_TICKET,
    QUERY,
    WHOAMI,
    DCSYNC,
    FINDACLS,
    NONE
};

class ArgumentParser {
    // Generic / shared options
    User user;
    std::string DC;
    std::string ip;
    std::string file_path;
    Modules currentModule = Modules::NONE;
    // Analysis::Query
    std::string query;
    std::vector<std::string> customAttributes;
    // Analysis::FindAcls
    std::vector<std::string> customTargets;
    bool scanAll = false;

    void transformUserDomain();
public:
    User getUser() const { return user; }
    std::string getDC() const { return DC; }
    std::string getIP() const { return ip; }
    Modules getModuleToRun() const { return currentModule; }
    std::string getFilePath() const { return file_path; }

    std::string getQuery() const { return query; }
    std::vector<std::string> getAttributes() const { return customAttributes; }

    std::vector<std::string> getCustomTargets() const { return customTargets; }
    bool getScanAll() const { return scanAll; }


    std::string makeBaseDN() const;
    bool parse(int argc, char* argv[]);
    void printHelp();
};