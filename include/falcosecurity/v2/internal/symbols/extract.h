#pragma once

#include <memory>
#include <string>
#include "../../types.h"
#include "../api.h"
#include "../base_plugin.h"
#include "../hacks.h"

namespace falcosecurity {
namespace _internal {

#define REGISTER_SYM_PLUGIN_EXTRACT_FIELDS(__t)                               \
    extern "C" falcosecurity::_internal::ss_plugin_rc plugin_extract_fields(  \
        falcosecurity::_internal::ss_plugin_t* s,                             \
        const falcosecurity::_internal::ss_plugin_event_input* evt,           \
        const falcosecurity::_internal::ss_plugin_field_extract_input* in) {  \
        return falcosecurity::_internal::ss_plugin_rc::SS_PLUGIN_FAILURE;     \
    }                                                                         \
                                                                              \
    extern "C" const char* plugin_get_fields() {                              \
        return "[{\"type\": \"uint64\", \"name\": \"test.field\", \"desc\": " \
               "\"Describing test field\"}]";                                 \
    }

};  // namespace _internal
};  // namespace falcosecurity
