CC = gcc
FLAGS = -g 

all: toy_server toy_nopie

toy_server: toy_server.c
	$(CC) $(FLAGS) $< -o $@

toy_nopie: toy_server.c
	$(CC) $(FLAGS) -no-pie $< -o $@

clean:
	rm toy_server toy_nopie