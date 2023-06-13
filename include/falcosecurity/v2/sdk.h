#pragma once

#include "internal/symbols/extract.h"
#include "internal/symbols/info.h"
#include "internal/symbols/init.h"
#include "internal/symbols/lasterr.h"

#define REGISTER_PLUGIN(__t)                \
    REGISTER_SYM_PLUGIN_INFOS(__t)          \
    REGISTER_SYM_PLUGIN_GET_LAST_ERROR(__t) \
    REGISTER_SYM_PLUGIN_INIT(__t)           \
    REGISTER_SYM_PLUGIN_EXTRACT_FIELDS(__t) \
    REGISTER_SYM_PLUGIN_DESTROY(__t)
