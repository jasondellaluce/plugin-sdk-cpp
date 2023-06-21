#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** arg)
{
    void* dl = dlopen("./libtest.so", RTLD_NOW);
    if(!dl)
    {
        fprintf(stderr, "ERROR: %s\n", dlerror());
        exit(1);
    }

    char* (*get_required_api_version)() =
            (char* (*)())dlsym(dl, "plugin_get_required_api_version");
    printf("%s\n", get_required_api_version());
}