NAME	=	my_module.so

SRCS	=	module.c \

OBJS	=	$(SRCS:.c=.o)

CFLAGS	=	-Wall -Wextra -fPIC

LDFLAGS	=	-lpam -lpam_misc -shared

CC	=	gcc

RM	=	rm -f

$(NAME):	$(OBJS)
		$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

all:	$(NAME)

clean:
	$(RM) $(OBJS)

fclean:	clean
	$(RM) $(NAME)

re: fclean all
