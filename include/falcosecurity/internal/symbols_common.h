/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <falcosecurity/internal/plugin_mixin.h>

#define FALCOSECURITY_PLUGIN(__t)                                              \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    using FALCOSECURITY_UNIQUEPREFIX(common_plugin_alias) = __t;               \
                                                                               \
    static plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(common_plugin_alias)>       \
            s_plugin_common;                                                   \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_required_api_version()                              \
    {                                                                          \
        return s_plugin_common.get_required_api_version();                     \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_version() { return s_plugin_common.get_version(); } \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_name() { return s_plugin_common.get_name(); }       \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_description()                                       \
    {                                                                          \
        return s_plugin_common.get_description();                              \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_contact() { return s_plugin_common.get_contact(); } \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_init_schema(ss_plugin_schema_type* st)              \
    {                                                                          \
        return s_plugin_common.get_init_schema(st);                            \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_last_error(ss_plugin_t* s)                          \
    {                                                                          \
        auto p = static_cast<plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(          \
                common_plugin_alias)>*>(s);                                    \
        return p->get_last_error();                                            \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    ss_plugin_t* plugin_init(const ss_plugin_init_input* input,                \
                             ss_plugin_rc* rc)                                 \
    {                                                                          \
        auto res = new plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(                \
                common_plugin_alias)>();                                       \
        *rc = res->init(input);                                                \
        return static_cast<ss_plugin_t*>(res);                                 \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    void plugin_destroy(ss_plugin_t* s)                                        \
    {                                                                          \
        auto p = static_cast<plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(          \
                common_plugin_alias)>*>(s);                                    \
        p->destroy();                                                          \
        delete p;                                                              \
    }                                                                          \
                                                                               \
    FALCOSECURITY_INLINE                                                       \
    static void plugin_symbols_common(plugin_api* out)                         \
    {                                                                          \
        out->get_required_api_version = plugin_get_required_api_version;       \
        out->get_version = plugin_get_version;                                 \
        out->get_description = plugin_get_description;                         \
        out->get_contact = plugin_get_contact;                                 \
        out->get_name = plugin_get_name;                                       \
        out->get_init_schema = plugin_get_init_schema;                         \
        out->get_last_error = plugin_get_last_error;                           \
        out->init = plugin_init;                                               \
        out->destroy = plugin_destroy;                                         \
    }                                                                          \
                                                                               \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
