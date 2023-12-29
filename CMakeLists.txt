cmake_minimum_required(VERSION 3.22)

set(CMAKE_C_COMPILER /usr/bin/clang)
project(ft_malcolm C)

if (VERBOSE)
    add_compile_options(-DVERBOSE=1)
endif ()
add_subdirectory(src/libft)
add_compile_options(-Wall -Werror -Wextra)
include_directories(./inc src/libft/inc)
add_executable(ft_malcolm
        src/main.c
        inc/ft_malcolm.h
        src/utils.c
        src/arp.c)
target_link_libraries(ft_malcolm ft)