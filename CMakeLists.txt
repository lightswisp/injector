cmake_minimum_required(VERSION 3.10.0)
project(injector)

add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
add_compile_options(-Wall -Wextra -Wpedantic)
add_link_options(-fsanitize=address,undefined)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(zydis)
add_executable(injector injector.c)
target_link_libraries(injector PRIVATE "Zydis")

