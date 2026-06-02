#include "ModuleGenerator.h"

#include "core/ModuleRegistry.h"

// Thin facade over ModuleRegistry. Module factories are registered by each
// module's own translation unit (see the Registrar in every module .cpp), so
// this function never needs to change when a module is added.
std::unique_ptr<Module> ModuleFactory::createModule(const ModuleFactoryContext& ctx) {
    return ModuleRegistry::instance().create(ctx);
}
