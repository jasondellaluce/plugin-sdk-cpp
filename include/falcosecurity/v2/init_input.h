#pragma once

#include "internal/hacks.h"
#include "types.h"

namespace falcosecurity {

class init_input {
   public:
    init_input(const _internal::ss_plugin_init_input* i) : m_input(i) {}
    init_input(init_input&&) = default;
    init_input& operator=(init_input&&) = default;
    init_input(const init_input&) = default;
    init_input& operator=(const init_input&) = default;
    virtual ~init_input() = default;

    INLINE const char* config() const { return m_input->config; }

    // todo: all accessors

   private:
    const _internal::ss_plugin_init_input* m_input;
};

};  // namespace falcosecurity
