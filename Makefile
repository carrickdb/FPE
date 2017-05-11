all: main.c enc.o enc.h
	gcc -o a main.c enc.o -lcrypto -I.


