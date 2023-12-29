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

fclean:
	@docker stop $$(docker ps -qa) > /dev/null 2> /dev/null ;\
	docker rm $$(docker ps -qa) > /dev/null 2> /dev/null;\
	docker rmi -f $$(docker images -qa) > /dev/null 2> /dev/null;\
	docker volume rm $$(docker volume ls -q) > /dev/null 2> /dev/null;\
	docker network prune -f > /dev/null 2> /dev/null;
	@yes | docker system prune -a

re:			fclean all

.PHONY: all clean fclean re 

.NOTPARALLEL: fclean
