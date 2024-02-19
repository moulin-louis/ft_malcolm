cmake_minimum_required(VERSION 3.22)

set(CMAKE_C_COMPILER /usr/bin/clang)
project(ft_malcolm C)

if (VERBOSE)
    add_compile_options(-DVERBOSE=1)
endif ()
add_subdirectory(src/libft)

include_directories(./inc ./src/libft/inc)

add_compile_options(-g -Wall -Wextra -Werror)

add_executable(ft_malcolm
        inc/ft_malcolm.h
        src/main.c
        src/utils.c
        src/arp.c)

target_link_libraries(ft_malcolm ft)