#pragma once

#include <stdexcept>
#include <string>
#include <vector>
#include "internal/hacks.h"
#include "types.h"

namespace falcosecurity {

class extract_request {
   public:
    extract_request(_internal::ss_plugin_extract_field* r = nullptr)
        : m_req(r), m_result(), m_result_strings() {}
    extract_request(extract_request&&) = default;
    extract_request& operator=(extract_request&&) = default;
    extract_request(const extract_request&) = default;
    extract_request& operator=(const extract_request&) = default;
    virtual ~extract_request() = default;

    INLINE void set_request(_internal::ss_plugin_extract_field* r) {
        if (!r) {
            throw std::invalid_argument(
                "invalid null pointer passed to extract request");
        }
        m_req = r;
    }

    INLINE uint64_t field_id() const { return m_req->field_id; }

    INLINE const char* field() const { return m_req->field; }

    INLINE field_value_type field_type() const {
        return static_cast<field_value_type>(m_req->ftype);
    }

    INLINE const char* arg_key() const { return m_req->arg_key; }

    INLINE uint64_t arg_index() const { return m_req->arg_index; }

    INLINE bool arg_present() const { return m_req->arg_present != 0; }

    INLINE bool is_list() const { return m_req->flist != 0; }

    template <typename Iter>
    INLINE void set_value(Iter begin, Iter end) {
        check_list(true);
        size_t i = 0;
        while (begin != end) {
            set_value(*begin, i);
            ++begin;
            ++i;
        }
    }

    INLINE void set_value(bool v) {
        check_list(false);
        set_value(v, 0);
    }

    INLINE void set_value(uint64_t v) {
        check_list(false);
        set_value(v, 0);
    }

    INLINE void set_value(const char* v) {
        check_list(false);
        set_value(v, 0);
    }

    INLINE void set_value(const std::string& v) {
        check_list(false);
        set_value(v, 0);
    }

   private:
    union result {
        const char* str;
        uint64_t u64;
        uint32_t u32;
        _internal::ss_plugin_bool boolean;
        _internal::ss_plugin_byte_buffer buf;
    };

    _internal::ss_plugin_extract_field* m_req;
    std::vector<result> m_result;
    std::vector<std::string> m_result_strings;

    INLINE void check_type(field_value_type t) const {
        if (t != field_type()) {
            throw std::invalid_argument(
                "invalid value type passed to extract request: expected=" +
                std::to_string(field_type()) + ", actual=" + std::to_string(t));
        }
    }

    INLINE void check_list(bool l) const {
        if (l != is_list()) {
            std::string prefix = l ? "expected" : "unexpected";
            throw std::invalid_argument(
                prefix + " list value type passed to extract request");
        }
    }

    INLINE void resize_result(size_t s) {
        if (m_result.size() < s) {
            m_result.resize(s);
            m_result_strings.resize(s);
        }
    }

    INLINE void set_value(bool v, size_t pos) {
        resize_result(pos);
        auto r = reinterpret_cast<_internal::ss_plugin_bool*>(m_result.data());
        r[pos] = (_internal::ss_plugin_bool)(v ? 1 : 0);
        m_req->res.boolean = &r[pos];
        m_req->res_len = pos;
    }

    INLINE void set_value(uint64_t v, size_t pos) {
        resize_result(pos);
        auto r = reinterpret_cast<uint64_t*>(m_result.data());
        r[pos] = v;
        m_req->res.u64 = &r[pos];
        m_req->res_len = pos;
    }

    INLINE void set_value(const char* v, size_t pos) {
        resize_result(pos);
        auto r = reinterpret_cast<const char**>(m_result.data());
        m_result_strings[pos].assign(v);
        r[pos] = m_result_strings[pos].c_str();
        m_req->res.str = &r[pos];
        m_req->res_len = pos;
    }

    INLINE void set_value(const std::string& v, size_t pos) {
        set_value(v.c_str(), pos);
    }

    // todo: reltime, abstime, ipaddr, ipnet
};

};  // namespace falcosecurity
