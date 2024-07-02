CC = gcc

all: create protest

protest: diskHash.c
	$(CC) -o mode diskHash.c mode.c

create:
	touch ./Hash_Table.txt ./Table_index.txt

clean:
	rm -f ./Hash_Table.txt ./Table_index.txt
