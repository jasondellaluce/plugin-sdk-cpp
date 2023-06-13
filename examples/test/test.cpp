#include <falcosecurity/v2/sdk.h>

struct my_plugin {

    falcosecurity::plugin_info info() const {
        falcosecurity::plugin_info info;
        info.name = "test";
        info.contact = "a";
        info.description = "b";
        info.version = "0.1.0";
        return info;
    }

    falcosecurity::result_code init(falcosecurity::init_input& in) {
        return falcosecurity::result_code::SS_PLUGIN_SUCCESS;
    }

    void set_last_error(const std::string& err) { m_lasterr = err; }

    const std::string& last_error() const { return m_lasterr; }

    std::string m_lasterr;
};

REGISTER_PLUGIN(my_plugin);