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

#define FALCOSECURITY_PLUGIN_EVENT_PARSING(__t)                                \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    using FALCOSECURITY_UNIQUEPREFIX(parsing_plugin_alias) = __t;              \
                                                                               \
    static plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(parsing_plugin_alias)>      \
            s_plugin_parsing;                                                  \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    uint16_t* plugin_get_parse_event_types(uint32_t* numtypes)                 \
    {                                                                          \
        return s_plugin_parsing.get_parse_event_types(numtypes);               \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    const char* plugin_get_parse_event_sources()                               \
    {                                                                          \
        return s_plugin_parsing.get_parse_event_sources();                     \
    }                                                                          \
                                                                               \
    FALCOSECURITY_API_SYMBOL                                                   \
    ss_plugin_rc plugin_parse_event(ss_plugin_t* s,                            \
                                    const ss_plugin_event_input* evt,          \
                                    const ss_plugin_event_parse_input* in)     \
    {                                                                          \
        auto p = static_cast<plugin_mixin<FALCOSECURITY_UNIQUEPREFIX(          \
                parsing_plugin_alias)>*>(s);                                   \
        return p->parse_event(evt, in);                                        \
    }                                                                          \
                                                                               \
    FALCOSECURITY_INLINE                                                       \
    static void plugin_symbols_async_events(plugin_api* out)                   \
    {                                                                          \
        out->get_parse_event_sources = plugin_get_parse_event_sources;         \
        out->get_parse_event_types = plugin_get_parse_event_types;             \
        out->parse_event = plugin_parse_event;                                 \
    }                                                                          \
                                                                               \
    }; /* _internal */                                                         \
    }; /* falcosecurity */
