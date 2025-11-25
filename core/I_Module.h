#pragma once
#include "../protocols/LDAPConnection.h"
#include "../cli/ArgumentParser.h"
#include "Context.h"

class I_Module {
public:
    virtual ~I_Module() = default;
    virtual std::string getName() const = 0;
    virtual void run(const ModuleRuntimeContext& ctx) = 0;
};