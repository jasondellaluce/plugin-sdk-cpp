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

#define REGISTER_SYM_PLUGIN_INIT(__t)                                        \
    extern "C" falcosecurity::_internal::ss_plugin_t* plugin_init(           \
        const falcosecurity::_internal::ss_plugin_init_input* input,         \
        falcosecurity::_internal::ss_plugin_rc* rc) {                        \
        using _plugin_type = falcosecurity::_internal::base_plugin<__t>;     \
        std::string err;                                                     \
        std::unique_ptr<_plugin_type> res = nullptr;                         \
        *rc = falcosecurity::_internal::ss_plugin_rc::SS_PLUGIN_FAILURE;     \
        CATCH_ANY_EXCEPTION(err, {                                           \
            res.reset(new _plugin_type());                                   \
            falcosecurity::init_input in(input);                             \
            falcosecurity::result_code* _rc =                                \
                static_cast<falcosecurity::result_code*>(rc);                \
            *_rc = res->init(in);                                            \
        });                                                                  \
        if (*rc !=                                                           \
                falcosecurity::_internal::ss_plugin_rc::SS_PLUGIN_SUCCESS && \
            !err.empty() && res) {                                           \
            res->set_last_error(err);                                        \
        }                                                                    \
        return static_cast<falcosecurity::_internal::ss_plugin_t*>(          \
            res.release());                                                  \
    }

#define REGISTER_SYM_PLUGIN_DESTROY(__t)                                       \
    extern "C" void plugin_destroy(falcosecurity::_internal::ss_plugin_t* s) { \
        auto p = static_cast<falcosecurity::_internal::base_plugin<__t>*>(s);  \
        delete p;                                                              \
    }

};  // namespace _internal
};  // namespace falcosecurity