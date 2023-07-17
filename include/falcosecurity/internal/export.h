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

#include <falcosecurity/internal/symbols_async.h>
#include <falcosecurity/internal/symbols_common.h>
#include <falcosecurity/internal/symbols_extraction.h>
#include <falcosecurity/internal/symbols_parsing.h>
#include <falcosecurity/internal/symbols_sourcing.h>

#ifndef FALCOSECURITY_STATIC
#define FALCOSECURITY_EXPORT()
#else // FALCOSECURITY_STATIC
#define FALCOSECURITY_EXPORT()                                                 \
                                                                               \
    namespace falcosecurity                                                    \
    {                                                                          \
    namespace _internal                                                        \
    {                                                                          \
                                                                               \
    static FALCOSECURITY_INLINE void plugin_symbols_common(...) {}             \
    static FALCOSECURITY_INLINE void plugin_symbols_event_sourcing(...) {}     \
    static FALCOSECURITY_INLINE void plugin_symbols_field_extraction(...) {}   \
    static FALCOSECURITY_INLINE void plugin_symbols_event_parsing(...) {}      \
    static FALCOSECURITY_INLINE void plugin_symbols_async_events(...) {}       \
                                                                               \
    extern "C" void FALCOSECURITY_UNIQUEPREFIX(get_plugin_api)(plugin_api *    \
                                                               out)            \
    {                                                                          \
        memset(out, 0, sizeof(plugin_api));                                    \
        plugin_symbols_common(out);                                            \
        plugin_symbols_event_sourcing(out);                                    \
        plugin_symbols_field_extraction(out);                                  \
        plugin_symbols_event_parsing(out);                                     \
        plugin_symbols_async_events(out);                                      \
    }                                                                          \
                                                                               \
    }; /* namespace _internal */                                               \
    }; /* namespace _internal */
#endif // FALCOSECURITY_STATIC