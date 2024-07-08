#ifndef ASDFAPI_EXT_INTERNAL_H
#define ASDFAPI_EXT_INTERNAL_H

#include <dlfcn.h>
#include "extensions/ext.h"

typedef int (*fnptr_ext_init)();

void *asdfapi_ext_load(struct ASDFExtension **info, const char *filename);
void *asdfapi_ext_call(void *handle, const char *sym);
void asdfapi_ext_show_descriptor(struct ASDFExtension *info);
#endif //ASDFAPI_EXT_INTERNAL_H

