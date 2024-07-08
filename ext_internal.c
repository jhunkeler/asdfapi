//
// Created by jhunk on 7/2/24.
//
#include "ext_internal.h"
#include "extensions/ext.h"

void asdfapi_ext_show_descriptor(struct ASDFExtension *info) {
    printf("Extension name: %s\n", info->name);
    printf("Extension description: %s\n", info->desc);
}

void *asdfapi_ext_load(struct ASDFExtension **info, const char *filename) {
    fnptr_ext_init ext_init;

    printf("Loading extension: %s\n", filename);
    void *handle_ext = dlopen(filename, RTLD_LAZY);
    if (handle_ext) {
        dlerror();
        ext_init = dlsym(handle_ext, "asdfapi_ext_init");
        if (ext_init) {
            (*ext_init)();
            dlerror();
            *info = dlsym(handle_ext, "asdfapi_ext_descriptor");
            if (!*info) {
                fprintf(stderr, "error reading extension descriptor: %s\n", dlerror());
                goto fail;
            }
        } else {
            fprintf(stderr, "error reading extension function: %s\n", dlerror());
            goto fail;
        }
    } else {
        fprintf(stderr, "error opening extension: %s\n", dlerror());
        goto fail;
    }
    return handle_ext;
    fail:
    return NULL;
}

void *asdfapi_ext_call(void *handle, const char *sym) {
    const char *prefix = "asdfapi_ext_";
    char name[255] = {0};
    snprintf(name, sizeof(name) - 1, "%s%s", prefix, sym);
    return dlsym(handle, name);
}
