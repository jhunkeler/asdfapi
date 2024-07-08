#include "ext.h"

struct ASDFExtension asdfapi_ext_descriptor;

int asdfapi_ext_say_hello(const char *msg) {
    printf("HELLO FROM %s:%s!\nMessage: %s\n", __FILE_NAME__, __FUNCTION__, msg);
    return 0;
}

int asdfapi_ext_init() {
    fprintf(stdout, "Initializing %s:%s\n", __FILE_NAME__ ,__FUNCTION__);
    asdfapi_ext_new(&asdfapi_ext_descriptor, "Hello", "An extension that prints a hello message");
    return 0;
}