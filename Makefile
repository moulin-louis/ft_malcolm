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
CC= /usr/bin/clang
all:
	mkdir -p cmake-build-debug
	cd cmake-build-debug && cmake .. && cd ..
	cmake --build cmake-build-debug --config Release -j 12
	docker compose up --build -d

clean:
	rm -rf ./build/CMakeFiles
	rm -rf ./build/libft
	rm -rf ./build/cmake_install.cmake
	rm -rf ./build/CMakeCache.txt
	rm -rf ./build/Makefile
	docker compose down

fclean:
	./clean.sh
	rm -rf cmake-build-debug

re:			fclean all

.PHONY: all clean fclean re 

.NOTPARALLEL: fclean
