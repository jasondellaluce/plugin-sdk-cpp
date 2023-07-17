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

#define FALCOSECURITY_PLUGIN_EVENT_SOURCING(__t, __i)                          \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    using FALCOSECURITY_UNIQUEPREFIX(sourcing_plugin_alias) = __t;             \
    using FALCOSECURITY_UNIQUEPREFIX(sourcing_instance_alias) = __i;           \
                                                                               \
    static plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(sourcing_plugin_alias)>     \
            s_plugin_sourcing;                                                 \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    uint32_t plugin_get_id() { return s_plugin_sourcing.get_id(); }            \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_event_source()                                      \
    {                                                                          \
        return s_plugin_sourcing.get_event_source();                           \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_list_open_params(ss_plugin_t* s, ss_plugin_rc* rc)      \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->list_open_params(rc);                                        \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_event_to_string(ss_plugin_t* s,                         \
                                       const ss_plugin_event_input* evt)       \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->event_to_string(evt);                                        \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    ss_instance_t* plugin_open(ss_plugin_t* s, const char* params,             \
                               ss_plugin_rc* rc)                               \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->open<FALCOSECURITY_UNIQUEPREFIX(sourcing_instance_alias)>(   \
                params, rc);                                                   \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    void plugin_close(ss_plugin_t* s, ss_instance_t* h)                        \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->close<FALCOSECURITY_UNIQUEPREFIX(sourcing_instance_alias)>(  \
                h);                                                            \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_progress(ss_plugin_t* s, ss_instance_t* h,          \
                                    uint32_t* progress_pct)                    \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->get_progress<FALCOSECURITY_UNIQUEPREFIX(                     \
                sourcing_instance_alias)>(h, progress_pct);                    \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* h,           \
                                   uint32_t* nevts, ss_plugin_event*** evts)   \
    {                                                                          \
        auto p = static_cast<plugin_mixin<__t>*>(s);                           \
        return p->next_batch<FALCOSECURITY_UNIQUEPREFIX(                       \
                sourcing_instance_alias)>(h, nevts, evts);                     \
    }                                                                          \
                                                                               \
    FALCOSECURITY_INLINE                                                       \
    static void plugin_symbols_event_sourcing(plugin_api* out)                 \
    {                                                                          \
        out->open = plugin_open;                                               \
        out->close = plugin_close;                                             \
        out->next_batch = plugin_next_batch;                                   \
        out->get_progress = plugin_get_progress;                               \
        out->event_to_string = plugin_event_to_string;                         \
        out->list_open_params = plugin_list_open_params;                       \
        out->get_event_source = plugin_get_event_source;                       \
        out->get_id = plugin_get_id;                                           \
    }                                                                          \
                                                                               \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
