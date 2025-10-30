#pragma once

#include <string>
#include "../attacks/Attacks.h"

typedef struct {
    std::string password;
    std::string username;
} User;

class ArgumentParser {
    User user;
    std::string DC;
    std::string ip;
    std::string file_path;
    AttackMethod attackMethod = NONE;

    void transformUserDomain();
public:
    ArgumentParser();


    User getUser() const;
    std::string getDC() const;
    std::string getIP() const;
    std::string getFilePath() const;
    AttackMethod getAttackMethod() const;


    std::string makeBaseDN() const;
    bool parse(int& argc, char* argv[]);
    void printHelp();
};