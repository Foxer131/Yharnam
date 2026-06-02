#pragma once
#include <functional>
#include <map>
#include <memory>

#include "cli/ArgumentParser.h"  // Modules enum
#include "core/Context.h"
#include "core/Module.h"

// Central registry mapping a Modules id to the factory that builds it.
//
// Each module registers its own factory from its .cpp via a static Registrar,
// so ModuleFactory stays closed for modification: adding a module no longer
// means editing a switch here. (Yharnam links every module .cpp directly into
// the executable, so these static registrars always run.)
class ModuleRegistry {
public:
    using Factory = std::function<std::unique_ptr<Module>(const ModuleFactoryContext&)>;

    static ModuleRegistry& instance();

    void registerFactory(Modules id, Factory factory);

    // Builds the module for ctx.moduleToRun, or nullptr if none is registered.
    std::unique_ptr<Module> create(const ModuleFactoryContext& ctx) const;

    // Registers a factory at static-initialisation time. Declare one in a
    // module's .cpp anonymous namespace to make the module self-registering.
    struct Registrar {
        Registrar(Modules id, Factory factory);
    };

private:
    ModuleRegistry() = default;
    std::map<Modules, Factory> factories_;
};
