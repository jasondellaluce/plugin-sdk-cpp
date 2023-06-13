#pragma once

#include <cstdint>
#include "internal/api.h"

namespace falcosecurity {

using result_code = _internal::ss_plugin_rc;

using event_type = uint16_t;

using init_schema_type = _internal::ss_plugin_schema_type;

using field_value_type = _internal::ss_plugin_field_type;

using state_value_type = _internal::ss_plugin_state_type;

};  // namespace falcosecurity