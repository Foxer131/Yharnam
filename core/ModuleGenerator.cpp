#include "ModuleGenerator.h"
#include "../modules/attacks/Attacks.h"
#include "../modules/analysis/Analysis.h"
#include "Context.h"
#include <memory>


std::unique_ptr<Module> ModuleFactory::createModule(const ModuleFactoryContext& ctx) {
    switch( ctx.moduleToRun) {
        case Modules::KERBEROAST:
            return std::make_unique<Attacks::Kerberoast>(
                ctx.ldapService,
                ctx.krbService,
                ctx.user.username,
                ctx.user.password
            );
        case Modules::ASREPROAST:
            return std::make_unique<Attacks::ASREPRoast>(
                ctx.ldapService
            );
        case Modules::QUERY:
            return std::make_unique<Analysis::Query>(
                ctx.ldapService,
                ctx.query,
                ctx.attrs
            );
        case Modules::WHOAMI:
            return std::make_unique<Analysis::Whoami>(
                ctx.ldapService,
                ctx.user.username
            );
        case Modules::FINDACLS:
            return std::make_unique<Analysis::FindAcls>(
                ctx.ldapService,
                ctx.aclService,
                ctx.user.username,
                ctx.customTargets,
                ctx.scanAll
            );
        case Modules::NONE:
        default:
            return nullptr;
    }
}
