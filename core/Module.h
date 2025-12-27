#pragma once
#include "../protocols/LdapConnection.h"
#include "../cli/ArgumentParser.h"
#include "Context.h"

class Module {
public:
    virtual ~Module() = default;
    virtual std::string getName() const = 0;
    virtual void run(const ModuleRuntimeContext& ctx) = 0;
};