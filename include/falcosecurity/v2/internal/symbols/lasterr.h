#pragma once

#include <memory>
#include <string>
#include "../../init_input.h"
#include "../../types.h"
#include "../api.h"
#include "../base_plugin.h"
#include "../hacks.h"

namespace falcosecurity {
namespace _internal {

#define REGISTER_SYM_PLUGIN_GET_LAST_ERROR(__t)                               \
    extern "C" const char* plugin_get_last_error(                             \
        falcosecurity::_internal::ss_plugin_t* s) {                           \
        auto p = static_cast<falcosecurity::_internal::base_plugin<__t>*>(s); \
        p->m_last_err_storage = p->last_error();                              \
        return p->m_last_err_storage.c_str();                                 \
    }

};  // namespace _internal
};  // namespace falcosecurity