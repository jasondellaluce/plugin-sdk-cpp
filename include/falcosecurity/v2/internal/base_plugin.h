#pragma once

#include <string>
#include <vector>
#include "../extract_request.h"
#include "../types.h"

namespace falcosecurity {
namespace _internal {

template <class Base>
struct base_plugin : public Base {
    std::string m_last_err_storage;
    std::vector<extract_request> m_extract_requests;
};

};  // namespace _internal
};  // namespace falcosecurity
