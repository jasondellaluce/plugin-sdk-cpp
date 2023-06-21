#include <falcosecurity/sdk.h>
#include <atomic>
#include <thread>

struct my_event_source
{
    virtual ~my_event_source() = default;

    // (optional)
    double get_progress(std::string& fmt)
    {
        fmt = "0.00%";
        return 0.0;
    }

    falcosecurity::result_code next_event(falcosecurity::event_writer& evt)
    {
        falcosecurity::events::pluginevent_e_encoder enc;
        // enc.set_name("cppnotif1");
        enc.set_data((void*)"hello world", strlen("hello world") + 1);
        enc.encode(evt);
        return falcosecurity::result_code::SS_PLUGIN_SUCCESS;
    }
};

struct my_plugin
{
    virtual ~my_plugin() = default;

    // ---- COMMON

    // (optional)
    std::string get_required_api_version()
    {
        printf("get_required_api_version\n");
        return "3.0.0";
    }

    std::string get_name() { return "cpptest"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    falcosecurity::init_schema get_init_schema()
    {
        printf("get_init_schema\n");
        return falcosecurity::init_schema();
    }

    // (optional)
    std::string get_last_error() { return ""; }

    falcosecurity::table m_threads_table;
    falcosecurity::table_field m_threads_field_comm;

    bool init(falcosecurity::init_input& i)
    {
        using st = falcosecurity::state_value_type;
        printf("init -- start\n");
        for(const auto& t : i.tables().list_tables())
        {
            printf("TABLE=%s, key=%s\n", t.name.c_str(),
                   falcosecurity::to_string(t.key_type).c_str());
        }

        auto fields = i.tables().fields();
        m_threads_table =
                i.tables().get_table("threads", st::SS_PLUGIN_ST_INT64);
        for(const auto& f : m_threads_table.list_fields(fields))
        {
            printf("  FIELD=%s, key=%s\n", f.name.c_str(),
                   falcosecurity::to_string(f.field_type).c_str());
        }

        m_threads_field_comm = m_threads_table.get_field(
                fields, "comm", st::SS_PLUGIN_ST_STRING);

        printf("end -- start\n");
        return true;
    }

    // ---- EVENT PARSING

    // (optional)
    std::vector<falcosecurity::event_type> get_parse_event_types()
    {
        printf("get_parse_event_types\n");
        return {}; // async events
    }

    // (optional)
    std::vector<std::string> get_parse_event_sources()
    {
        printf("get_parse_event_sources\n");
        return {"syscall"};
    }

    uint64_t m_notif_count = 0;

    bool parse_event(const falcosecurity::parse_event_input& in)
    {
        auto& evt = in.get_event_reader();
        auto& tr = in.get_table_reader();
        auto& tw = in.get_table_writer();
        auto th = m_threads_table.get_entry(tr, (int64_t)evt.get_tid());
        std::string comm;
        m_threads_field_comm.read_value(tr, th, comm);
        m_threads_field_comm.write_value(tw, th, comm);
        // printf("comm=%s\n", comm.c_str());
        if(evt.get_type() == 402)
        {
            falcosecurity::events::asyncevent_e_decoder dec(evt);
            if(strcmp(dec.get_name(), "cppnotif") == 0)
            {
                m_notif_count++;
            }
        }
        return true;
    }

    // ---- FIELD EXTRACTION

    // (optional)
    std::vector<falcosecurity::event_type> get_extract_event_types()
    {
        printf("get_extract_event_types\n");
        return {};
    }

    // (optional)
    std::vector<std::string> get_extract_event_sources()
    {
        printf("get_extract_event_sources\n");
        return {"syscall"};
    }

    std::vector<falcosecurity::field_info> get_fields()
    {
        printf("get_fields\n");
        using ft = falcosecurity::field_value_type;
        return {
                {ft::FTYPE_STRING, "cpp.field", "some display name",
                 "some cool sample field"},
                {ft::FTYPE_UINT64, "cpp.notifcount", "some display name",
                 "some cool sample field"},
        };
    }

    bool extract(const falcosecurity::extract_fields_input& in)
    {
        auto& evt = in.get_event_reader();
        auto& tr = in.get_table_reader();
        auto& req = in.get_extract_request();
        auto th = m_threads_table.get_entry(tr, (int64_t)evt.get_tid());
        std::string comm;
        m_threads_field_comm.read_value(tr, th, comm);
        // printf("COMM=%s\n", comm.c_str());
        switch(req.get_field_id())
        {
        case 0: // cpp.field
            req.set_value("sampleval");
            return true;
        case 1: // cpp.notifcount
            req.set_value(m_notif_count);
            return true;
        default:
            return false;
        }
    }

    // ---- ASYNC EVENTS

    std::vector<std::string> get_async_events()
    {
        printf("get_async_events\n");
        return {"cppnotif"};
    }

    // (optional)
    std::vector<std::string> get_async_event_sources()
    {
        printf("get_async_event_sources\n");
        return {"syscall"};
    }

    std::thread m_async_thread;
    std::atomic<bool> m_stop_async_thread;

    bool start_async_events(falcosecurity::event_writer& w,
                            std::function<void(void)> submit)
    {
        printf("start_async_events\n");
        m_stop_async_thread = false;
        m_async_thread = std::thread(
                [this, &w, submit]()
                {
                    uint64_t count = 0;
                    std::string msg;
                    falcosecurity::events::asyncevent_e_encoder enc;
                    while(!m_stop_async_thread)
                    {
                        msg = "hello world #" + std::to_string(count++);
                        enc.set_name("cppnotif");
                        enc.set_data((void*)msg.c_str(), msg.size() + 1);
                        enc.encode(w);
                        submit();
                        std::this_thread::sleep_for(
                                std::chrono::milliseconds(1000));
                    }
                });
        return true;
    }

    bool stop_async_events() noexcept
    {
        printf("stop_async_events\n");
        m_stop_async_thread = true;
        if(m_async_thread.joinable())
        {
            m_async_thread.join();
        }
        return true;
    }

    // EVENT SOURCING

    // (optional)
    uint32_t get_id() { return 999; };

    // (optional)
    std::string get_event_source() { return "cpptest"; };

    // (optional)
    std::vector<falcosecurity::open_param> list_open_params() { return {}; }

    // (optional)
    std::string event_to_string(const falcosecurity::event_reader& evt)
    {
        return "evt num: " + std::to_string(evt.get_num());
    }

    std::unique_ptr<my_event_source> open(const std::string&)
    {
        return std::unique_ptr<my_event_source>(new my_event_source());
    }
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_SOURCING(my_plugin, my_event_source);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
