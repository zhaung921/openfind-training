CC=gcc

CFLAGS=-g

TARGET=mode

SOURCES=mode.c diskHash.c

all: $(TARGET) check_files

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

check_files:
	@test -f Hash_Table.txt || touch Hash_Table.txt
	@test -f Table_index.txt || touch Table_index.txt

# 清理编译生成的文件
clean:
	rm -f $(TARGET) Hash_Table.txt Table_index.txt