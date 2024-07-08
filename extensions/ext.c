//
// Created by jhunk on 7/2/24.
//
#include "ext.h"

int asdfapi_ext_new(struct ASDFExtension *ext, const char *name, const char *desc) {
    ext->name = name;
    ext->desc = desc;
    return 0;
}
