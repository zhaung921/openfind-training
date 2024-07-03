CC = gcc
CFLAGS = -Wall
SQLITE_DIR = ../sqlite-amalgamation-3460000
SQLITE_LIB = $(SQLITE_DIR)/libsqlite3.a

all: myprogram

myprogram:	test_main.o $(SQLITE_LIB)
	$(CC) -o myprogram test_main.o $(SQLITE_LIB)

test_main.o: test_main.c
	$(CC) $(CFLAGS) -I$(SQLITE_DIR) -c test_main.c -o test_main.o -L$(SQLITE_DIR) 

clean:
	rm -f test_main.o myprogram
