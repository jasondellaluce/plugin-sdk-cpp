#pragma once
#include <string>
#include "../../info.h"
#include "../../types.h"
#include "../api.h"
#include "../base_plugin.h"
#include "../hacks.h"

namespace falcosecurity {
namespace _internal {

#define REGISTER_SYM_PLUGIN_INFOS(__t)                                      \
    static falcosecurity::plugin_info s_plugin_info =                       \
        falcosecurity::_internal::base_plugin<__t>().info();                \
                                                                            \
    extern "C" const char* plugin_get_required_api_version() {              \
        return s_plugin_info.required_api_version.c_str();                  \
    }                                                                       \
                                                                            \
    extern "C" const char* plugin_get_version() {                           \
        return s_plugin_info.version.c_str();                               \
    }                                                                       \
                                                                            \
    extern "C" const char* plugin_get_name() {                              \
        return s_plugin_info.name.c_str();                                  \
    }                                                                       \
                                                                            \
    extern "C" const char* plugin_get_description() {                       \
        return s_plugin_info.description.c_str();                           \
    }                                                                       \
                                                                            \
    extern "C" const char* plugin_get_contact() {                           \
        return s_plugin_info.contact.c_str();                               \
    }                                                                       \
                                                                            \
    extern "C" const char* plugin_get_init_schema(                          \
        falcosecurity::_internal::ss_plugin_schema_type* st) {              \
        *st = static_cast<falcosecurity::_internal::ss_plugin_schema_type>( \
            s_plugin_info.init_schema_typeval);                             \
        return s_plugin_info.init_schema.c_str();                           \
    }

};  // namespace _internal
};  // namespace falcosecurity
