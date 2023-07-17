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

#define FALCOSECURITY_INLINE __attribute__((always_inline)) inline

#if defined(FALCOSECURITY_STATIC)
#define FALCOSECURITY_API_SYMBOL static FALCOSECURITY_INLINE
#define FALCOSECURITY_UNIQUEPREFIX_ FALCOSECURITY_STATIC
#else // defined(FALCOSECURITY_STATIC)
#define FALCOSECURITY_API_SYMBOL extern "C"
#define FALCOSECURITY_UNIQUEPREFIX_
#endif // defined(FALCOSECURITY_STATIC)

#define FALCOSECURITY_CONCAT_(__x, __y) __x##__y

#define FALCOSECURITY_CONCAT(__x, __y) FALCOSECURITY_CONCAT_(__x, __y)

#define FALCOSECURITY_UNIQUEPREFIX(__x)                                        \
    FALCOSECURITY_CONCAT(FALCOSECURITY_UNIQUEPREFIX_, __x)

#if defined(_DEBUG) or defined(DEBUG)
#define FALCOSECURITY_ASSERT(__x, __msg)                                       \
    {                                                                          \
        if(!(__x))                                                             \
        {                                                                      \
            fprintf(stderr,                                                    \
                    "fatal: plugin-sdk-cpp failed debug assertion: %s\n",      \
                    std::string(__msg).c_str());                               \
            exit(-1);                                                          \
        }                                                                      \
    }
#else
#define FALCOSECURITY_ASSERT(__x, __msg)
#endif

#define FALCOSECURITY_CATCH_ALL(errdest, block)                                \
    try                                                                        \
    {                                                                          \
        block;                                                                 \
    }                                                                          \
    catch(std::exception & e)                                                  \
    {                                                                          \
        errdest = e.what();                                                    \
    }                                                                          \
    catch(...)                                                                 \
    {                                                                          \
        errdest = "unknown runtime error";                                     \
    }
