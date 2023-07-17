#include <cstdio>

#include <falcosecurity/sdk.h>

using api_t = falcosecurity::_internal::plugin_api;

extern "C" void source_get_plugin_api(api_t*);
extern "C" void extract_get_plugin_api(api_t*);

void print_api(api_t* out)
{
    falcosecurity::_internal::ss_plugin_rc a;
    falcosecurity::_internal::ss_plugin_init_input i;
    out->init(&i, &a);
    printf("API for %s\n", out->get_name());
    printf("get_required_api_version: %p\n", out->get_required_api_version);
    printf("get_version: %p\n", out->get_version);
    printf("get_description: %p\n", out->get_description);
    printf("get_contact: %p\n", out->get_contact);
    printf("get_name: %p\n", out->get_name);
    printf("get_init_schema: %p\n", out->get_init_schema);
    printf("get_last_error: %p\n", out->get_last_error);
    printf("init: %p\n", out->init);
    printf("destroy: %p\n", out->destroy);
    printf("get_async_events: %p\n", out->get_async_events);
    printf("get_async_event_sources: %p\n", out->get_async_event_sources);
    printf("set_async_event_handler: %p\n", out->set_async_event_handler);
    printf("get_extract_event_types: %p\n", out->get_extract_event_types);
    printf("get_extract_event_sources: %p\n", out->get_extract_event_sources);
    printf("get_fields: %p\n", out->get_fields);
    printf("extract_fields: %p\n", out->extract_fields);
    printf("get_parse_event_sources: %p\n", out->get_parse_event_sources);
    printf("get_parse_event_types: %p\n", out->get_parse_event_types);
    printf("parse_event: %p\n", out->parse_event);
    printf("open: %p\n", out->open);
    printf("close: %p\n", out->close);
    printf("next_batch: %p\n", out->next_batch);
    printf("get_progress: %p\n", out->get_progress);
    printf("event_to_string: %p\n", out->event_to_string);
    printf("list_open_params: %p\n", out->list_open_params);
    printf("get_event_source: %p\n", out->get_event_source);
    printf("get_id: %p\n", out->get_id);
    printf("\n");
}

int main(int argc, char** argv)
{
    api_t source_example;
    source_get_plugin_api(&source_example);
    print_api(&source_example);

    api_t extract_example;
    extract_get_plugin_api(&extract_example);
    print_api(&extract_example);
    return 0;
}
