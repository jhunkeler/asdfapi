cmake_minimum_required(VERSION 3.28)
project(asdfapi C)

set(CMAKE_C_STANDARD 99)

link_libraries(dl)
add_subdirectory(extensions)
add_executable(asdfapi main.c
        ext_internal.c
        ext_internal.h
)
