//
// Created by jhunk on 7/2/24.
//

#ifndef ASDFAPI_EXT_H
#define ASDFAPI_EXT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ASDFExtension {
    const char *name;   // Name of extension
    const char *desc;   // Description of extension
};

int asdfapi_ext_new(struct ASDFExtension *ext, const char *name, const char *desc);
#endif //ASDFAPI_EXT_H
