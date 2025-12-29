#include "Analysis.h"
#include "../../utils/Colors.h"
#include "../../protocols/LdapQuerier.h"
#include <iostream>
#include <iomanip>

Analysis::Query::Query(LdapQuerier& _ldap, 
    const std::string& _query, 
    const std::vector<std::string>& _attrs)
    : ldap(_ldap), 
    queryFilter(_query), 
    attributesToFetch(_attrs) 
{}

void Analysis::Query::run(const ModuleRuntimeContext& ctx) {
    if (queryFilter.empty()) {
        std::cerr << "[-] Error: No query specified. Use --query \"(filter)\"" << std::endl;
        return;
    }

    std::cout << "[*] Executing Custom Query: " << queryFilter << std::endl;
    if (!attributesToFetch.empty()) {
        std::cout << "[*] Filtered Attributes: ";
        for(const auto& a : attributesToFetch) std::cout << a << " ";
        std::cout << std::endl;
    } else {
        std::cout << "[*] Fetching ALL attributes (*)" << std::endl;
    }

    auto results = ldap.executeQueryAndUnpackData(ctx.baseDN, queryFilter, attributesToFetch);
    displayResults(results);
}

void Analysis::Query::displayResults(const LDAPResult& results) {
    if (results.empty()) {
        std::cout << "[-] No objects found." << std::endl;
        return;
    }

    std::cout << "\n" << Colors::COLOR_GREEN << "[+] Found " << results.size() << " objects:" << Colors::COLOR_RESET << "\n";

    int count = 1;
    for (const auto& objectMap : results) {
        std::cout << "Object #" << count++ << "\n";
        
        for (const auto& [attrName, values] : objectMap) {
            std::cout << Colors::COLOR_YELLOW << "  " << std::left << std::setw(25) << attrName << ": " << Colors::COLOR_RESET;
            
            if (values.empty()) {
                std::cout << "(empty)\n";
            } else if (values.size() == 1) {
                std::cout << values[0] << "\n";
            } else {
                std::cout << "\n";
                for (const auto& val : values) {
                    std::cout << "    - " << val << "\n";
                }
            }
        }
    }
}