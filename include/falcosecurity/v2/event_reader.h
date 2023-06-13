#pragma once

#include <stdexcept>
#include <string>
#include "internal/hacks.h"
#include "types.h"

namespace falcosecurity {

class event_reader {
   public:
    event_reader(_internal::ss_plugin_event_input* i) : m_input(i) {}
    event_reader(event_reader&&) = default;
    event_reader& operator=(event_reader&&) = default;
    event_reader(const event_reader&) = default;
    event_reader& operator=(const event_reader&) = default;
    virtual ~event_reader() = default;

    INLINE event_type type() const { return m_input->evt->type; }

    INLINE event_type ts() const { return m_input->evt->ts; }

    INLINE uint64_t thread_id() const { return m_input->evt->tid; }

    INLINE uint64_t num() const { return m_input->evtnum; }

    INLINE const char* source() const { return m_input->evtsrc; }

    // todo: hide this?
    INLINE _internal::ss_plugin_event_input* input() const { return m_input; }

   private:
    _internal::ss_plugin_event_input* m_input;
};

// todo: autogenerate these for every event type
class pluginevent_event_reader {
    pluginevent_event_reader(const event_reader& r) : m_reader(r) {
        // todo: have all event codes somewhere
        if (r.type() != 322) {
            throw std::invalid_argument(
                "invalid event type conversion in event reader: requested=" +
                std::to_string(322) + ", actual=" + std::to_string(r.type()));
        }
    }
    pluginevent_event_reader(pluginevent_event_reader&&) = default;
    pluginevent_event_reader& operator=(pluginevent_event_reader&&) = delete;
    pluginevent_event_reader(const pluginevent_event_reader&) = default;
    pluginevent_event_reader& operator=(const pluginevent_event_reader&) =
        delete;
    virtual ~pluginevent_event_reader() = default;

    // todo: implement all accessors
    INLINE const uint32_t plugin_id() const { return 0; }

   private:
    const event_reader& m_reader;
};

};  // namespace falcosecurity
