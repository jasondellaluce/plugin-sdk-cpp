#pragma once

#include <stdexcept>
#include <string>
#include "internal/hacks.h"
#include "types.h"

namespace falcosecurity {

struct plugin_info {
    plugin_info()
        : required_api_version(PLUGIN_API_VERSION_STR),
          version(""),
          name(""),
          contact(""),
          description(""),
          init_schema(""),
          init_schema_typeval(init_schema_type::SS_PLUGIN_SCHEMA_NONE) {}
    plugin_info(plugin_info&&) = default;
    plugin_info& operator=(plugin_info&&) = default;
    plugin_info(const plugin_info&) = default;
    plugin_info& operator=(const plugin_info&) = default;
    virtual ~plugin_info() = default;

    std::string required_api_version;
    std::string version;
    std::string name;
    std::string contact;
    std::string description;
    std::string init_schema;
    init_schema_type init_schema_typeval;
};

};  // namespace falcosecurity