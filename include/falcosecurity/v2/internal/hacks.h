#pragma once

#define INLINE __attribute__((always_inline)) inline

#define CATCH_ANY_EXCEPTION(errdest, block) \
    try {                                   \
        block;                              \
    } catch (std::exception & e) {          \
        errdest = e.what();                 \
    }
