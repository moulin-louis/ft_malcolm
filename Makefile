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
	docker compose up --build -d

clean:
	docker compose down

fclean: clean
	-docker stop $(docker ps -qa) > /dev/null 2>&1
	-docker rm $(docker ps -qa) > /dev/null 2>&1
	-docker rmi -f $(docker images -qa) > /dev/null 2>&1
	-docker volume rm $(docker volume ls -q) > /dev/null 2>&1
	-docker network prune -f > /dev/null 2>&1
	-yes | docker system prune -a > /dev/null 2>&1

re:			fclean all

.PHONY: all clean fclean re 

.NOTPARALLEL: fclean
