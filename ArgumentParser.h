#pragma once

#include <string>
#include "Attacks.h"

typedef struct {
    std::string password;
    std::string username;
} User;

class ArgumentParser {
    User user;
    std::string DC;
    std::string ip;
    AttackMethod attackMethod = NONE;

public:
    ArgumentParser();


    User getUser() const;
    std::string getDC() const;
    std::string getIP() const;
    AttackMethod getAttackMethod() const;
    void printHelp();
    bool parse(int& argc, char* argv[]);
};