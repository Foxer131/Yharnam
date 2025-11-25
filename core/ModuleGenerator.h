#pragma once
#include <memory>
#include "I_Module.h"
#include "Context.h"

class ModuleFactory {
public:
    static std::unique_ptr<I_Module> createModule(const ModuleFactoryContext& ctx);
};