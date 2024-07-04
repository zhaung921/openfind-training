CC=gcc

CFLAGS=-g

LFLAG=-l

TARGET=web_client

SOURCES=web_client.c

LIB=ssl

LIB2=crypto

all: $(TARGET) 

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LFLAG)$(LIB) $(LFLAG)$(LIB2)

