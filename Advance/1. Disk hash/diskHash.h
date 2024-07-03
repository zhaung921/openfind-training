#ifndef MEMORY_HASH_H
#define MEMORY_HASH_H
#define MAX_KEY_LEN     256
#define MAX_VAL_LEN     4194304

typedef enum TYPE
{
    TYPE_INT,
    TYPE_STR,
    TYPE_BINARY
} TYPE;

typedef struct valType
{
    void *data;
    TYPE type;
    int valSize;
} valType;

typedef struct IndexEntry {
    char key[MAX_KEY_LEN];
    long offset;
    size_t length;
    TYPE type;
    int deleted; // 0: not deleted, 1: deleted
} IndexEntry;

extern int hash(char *currKey);                             // using to get hash value                                 
extern int insertUpdate(char *currKey, valType *currVal);   // insert/update data to index table and hash table
extern int add(char *fileName);                             // add key val from file to hash table also index table
extern int del(char *currKey);                              // del data in table                     
extern int query(char *currKey);                            // get value form table                           
extern int importFile(char *fileName, char *fileType);      // import file into hash table(string or binary)                                                       
extern int exportFile(char *currkey, char *fileName);       // export value to a file
extern int resetTable();                                    // reset table to really delete and update data                           
#endif
