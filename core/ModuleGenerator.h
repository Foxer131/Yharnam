#pragma once
#include <memory>
#include "Module.h"
#include "Context.h"

class ModuleFactory {
public:
    static std::unique_ptr<Module> createModule(const ModuleFactoryContext& ctx);
};