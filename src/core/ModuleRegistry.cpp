#include "core/ModuleRegistry.h"

ModuleRegistry& ModuleRegistry::instance() {
    static ModuleRegistry registry;
    return registry;
}

void ModuleRegistry::registerFactory(Modules id, Factory factory) {
    factories_[id] = std::move(factory);
}

std::unique_ptr<Module> ModuleRegistry::create(const ModuleFactoryContext& ctx) const {
    auto it = factories_.find(ctx.moduleToRun);
    if (it == factories_.end()) {
        return nullptr;
    }
    return it->second(ctx);
}

ModuleRegistry::Registrar::Registrar(Modules id, Factory factory) {
    ModuleRegistry::instance().registerFactory(id, std::move(factory));
}
