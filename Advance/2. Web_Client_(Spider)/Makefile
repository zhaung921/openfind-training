CC=gcc

CFLAGS=-g

LFLAG=-l

TARGET=web_client

SOURCES=web_client.c

LIB=ssl

LIB2=crypto

all: $(TARGET) creat_file

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -I/usr/include/libxml2 -o $(TARGET) $(SOURCES) $(LFLAG)$(LIB) $(LFLAG)$(LIB2)

creat_file:
	@test -d openfind_output || mkdir -p openfind_output
clean:
	rm -r openfind_output

