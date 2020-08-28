NAME      = auth_plugin_http
INC       = -I. -I /libs -I /libs
CFLAGS    = -Wall -Werror -fPIC
DEBUG     = -DDEBUG_INFO
LIBS      = -lcurl -ljson-c

all: $(NAME).so

$(NAME).so: $(NAME).o
	$(CC) $(CFLAGS) $(INC) -shared $^ -o $@ $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(DEBUG) $(INC) $< -o $@

clean:
	rm -f *.o *.so