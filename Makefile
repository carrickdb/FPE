all: main.c enc.o enc.h
	gcc -o a main.c enc.o -lm -lcrypto -I.


clean: 
	rm -f *.o enc
