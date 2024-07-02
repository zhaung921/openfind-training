#ifndef MEMORY_HASH_H
#define MEMORY_HASH_H
#define MAX_KEY_LEN     255
#define MAX_VAL_LEN     4194304

typedef enum TYPE
{
    TYPE_INT,
    TYPE_STR,
    TYPE_BINARY
} TYPE;

typedef struct valDataType
{
    void *data;
    TYPE type;
    int valSize;
} valDataType;

typedef struct ListNode
{
    char key[MAX_KEY_LEN + 1];
    valDataType val;
    struct ListNode *next;
} ListNode;

typedef struct hashTable
{
    ListNode **slot;
    int size;
    int dataCount;
    int collision;
} hashTable;

extern ListNode *initNode(char *currKey, void *currVal, int valSzie, TYPE currType);
extern hashTable *initHashTable(int tableSize);
extern int hashFunction(char *currKey);                                                             // return hash vale base on key
extern int insertUpdate(hashTable *ht, char *currKey, void *currVal, int valSzie, TYPE currType);   // insert or update base on it's type and valLen
extern int delete(hashTable *ht, char *currKey);                                                    // delete key and it's val
extern valDataType *search(hashTable *ht, char *currKey);                                           // return it's val if key exist otherwise return NULL
extern int printVal(valDataType *currVal);                                                          // print val depend on it's type.valLen can be NULL if val not binary data
extern int destroyTable(hashTable *ht);                                                             // delete all data in table
extern int resize(valDataType *oldVal, int newLen, TYPE newType);                                   // relocate memory for data                                    
#endif
