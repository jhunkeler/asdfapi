project(asdfapi_ext)
add_library(asdfapi_ext SHARED ext.c ext.h)
add_library(asdfapi_ext_hello SHARED ext_hello.c)
target_link_libraries(asdfapi_ext_hello asdfapi_ext)