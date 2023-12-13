# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: loumouli <loumouli@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2023/01/13 13:30:11 by loumouli          #+#    #+#              #
#    Updated: 2023/02/15 11:49:33 by loumouli         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #
all:
	mkdir -p build
	cd build && cmake .. && cd ..
	cmake --build build --config Release -j 12

clean:
	rm -rf ./build/CMakeFiles
	rm -rf ./build/libft
	rm -rf ./build/cmake_install.cmake
	rm -rf ./build/CMakeCache.txt
	rm -rf ./build/Makefile

fclean:
	rm -rf build

re:			fclean all

.PHONY: all clean fclean re 

.NOTPARALLEL: fclean