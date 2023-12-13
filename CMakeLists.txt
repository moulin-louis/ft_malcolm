cmake_minimum_required(VERSION 3.22)
project(ft_malcolm C)

set(CMAKE_C_STANDARD 23)

add_subdirectory(libft)
add_compile_options(-Wall -Werror -Wextra -Weverything)
include_directories(./inc ./libft/inc)
add_executable(ft_malcolm
        src/main.c
        inc/ft_malcolm.h
        src/utils.c
        src/arp.c)