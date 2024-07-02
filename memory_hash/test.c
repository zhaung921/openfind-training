#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "memory_hash.h"

#define SUCCESS               0
#define ERR_BASE             -1
#define ERR_MALLOC_FAIL     ERR_BASE - 1
#define MAX_TABLE_SIZE      120910 
#define INT_LEN               1

void test_insert(hashTable *ht)
{
    char value[] = { 0x41, 0x0, 0x43};
    printf("test_insert for key: %s, [0x%x,0x%x,0x%x]\n", "key_a", value[0], value[1], value[2]);
    insertUpdate(ht, "key_a", value, sizeof(value), TYPE_BINARY);    
    return;
}

void test_search(hashTable *ht)
{
    valDataType *value;
    value = search(ht, "key_a");
    printVal(value);
    
    return;
}

int main()
{
    hashTable *ht = initHashTable(MAX_TABLE_SIZE);
    if (!ht)
    {
        printf("main() hash table creat fail\n");
        return ERR_MALLOC_FAIL;
    }
    // test begin

    test_insert(ht);                                                //function test
    test_search(ht);

    long long int testInt = 1234;

    char testBinary[]={ 0x41, 0x42, 0x00, 0x44 };                   // binary data should use hex form
    int binaryLen=sizeof(testBinary);                               

    char testStr[]="das1 -=12xassadcw 4651qw5dq1wdqw561d65qw1d1qd6q1d61dsadwd";
    int strLen=strlen(testStr);

    insertUpdate(ht, "int", &testInt, INT_LEN, TYPE_INT);             // insert int data intlen
    insertUpdate(ht, "code", testBinary, binaryLen, TYPE_BINARY);     // insert binary data (hex form)
    insertUpdate(ht, "str", testStr, strLen, TYPE_STR);               // insert str data
                                                  
    printVal(search(ht,"code"));                                      // combine printval and search to see val 
    printVal(search(ht,"int"));                                             
    printVal(search(ht,"str"));
    
    valDataType *searchA;                                             //val can still be hold even after call delete  
    searchA=search(ht,"str");
    delete(ht, "str");
    printVal(searchA);   
    

    if(searchA)                                                       //if use search and get a return value then must free return val
    {
        free (searchA->data);
        searchA->data = NULL;
        free (searchA);
        searchA = NULL;
    }
      
    
    return SUCCESS;
}
