#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "memory_hash.h"

#define SUCCESS                  0
#define ERR_BASE                -1
#define ERR_MALLOC_FAIL     ERR_BASE - 1
#define ERR_NULL            ERR_BASE - 2
#define ERR_NOT_FOUND       ERR_BASE - 3
#define ERR_OUT_OF_RANGE    ERR_BASE - 4
#define ERR_INITIAL_FAIL    ERR_BASE - 5

#define MAX_VAL_LEN         4194304
#define MAX_TABLE_SIZE      120910 
#define SEED                0x12345678       //for hash function's begin hash value

#define max(a, b) ((a) > (b) ? (a) : (b))

int pos = 0;                                //position of link list from slot's head for update or delete

ListNode *initNode(char *currKey, void *currVal, int valSize, TYPE currType) 
{
    ListNode *node = (ListNode *)malloc(sizeof(ListNode));
    if (!node)
    {
        printf("Error initNode() malloc fail.\n");
        return NULL;
    }

    node->next = NULL;
    node->val.data = NULL;
    strncpy(node->key, currKey, strlen(currKey));     //set keys
    node->key[strlen(currKey)] = '\0';

    resize(&node->val, valSize, currType);
    if (currType == TYPE_INT)                          //set int vals 
    {
        *(long long int *)node->val.data = *(long long int *)currVal;
    }
    else                    //set str vals   
    {
        memcpy(node->val.data, (char *)currVal,valSize+1);
        ((char*)node->val.data)[valSize]='\0';
    }
    return node;
}

hashTable *initHashTable(int tableSize)
{
    hashTable *table = (hashTable *)malloc(sizeof(hashTable));
    if (!table)
    {
        printf("Error initHash() malloc fail.\n");
        return NULL;
    }
    table->size = tableSize;
    table->dataCount = 0;
    table->collision = 0;
    table->slot = (ListNode **)calloc(table->size, sizeof(ListNode *));
    if (!table->slot)
    {
        printf("Error initHash() malloc fail.\n");
        return NULL;
    }

    for (int i = 0; i < table->size; i++)
        table->slot[i] = NULL;
    return table;
}

int hashFunction(char *currKey)
{
    unsigned int hash = SEED;
    while (*currKey != '\0')
        hash = 17000069 * hash + *currKey++;
    return hash % MAX_TABLE_SIZE;
}

int resize(valDataType *oldVal, int newLen, TYPE newType)
{
    free(oldVal->data);
    if(newType == TYPE_INT)
    {
         oldVal->data = (long long int* )malloc(sizeof(long long int));
    }
    else         
    {
        oldVal->data = (char* )malloc(sizeof(char)*newLen+1);
    }
    oldVal->type = newType;
    oldVal->valSize = newLen+1;
    return SUCCESS;
}

int insertUpdate(hashTable *ht, char *currKey, void *currVal, int valSize, TYPE currType)
{
    
    if (!ht)
    {
        printf("insertUpdate() hashTable is null.\n");
        return ERR_NULL;
    }
    if(!currKey || !currVal)
    {
        printf("insertUpdate() key or val is null.\n");
        return ERR_NULL;
    }
    if (valSize+1 >= MAX_VAL_LEN)           //check val size under 4mb
    {
        printf("Error out of range,val max is 4mb.\n");
        return ERR_OUT_OF_RANGE;
    }

    int index = hashFunction(currKey);
    valDataType *searchReturn = search(ht, currKey);
    
    if (searchReturn)                       //update val with currVal (search will set pos when found key)
    {
        
        ListNode *target = ht->slot[index];
        for (int i = 0; i < pos; i++)       //go to the target which should be update
        {
            target = target->next;
        }
        
        resize(&target->val, valSize, currType);
        if (currType == TYPE_INT)           //update int
        {
            *(long long int *)target->val.data = *(long long int *)currVal;
        }
        else                                //update str or binary
        {
            memcpy((char *)target->val.data, (char *)currVal, valSize+1);
            ((char*)target->val.data)[valSize] = '\0';
        }
        free (searchReturn->data);
        searchReturn->data = NULL;
        free (searchReturn);
        searchReturn = NULL;
    }
    else                                    //insert
    {
        ListNode *newNode = initNode(currKey, currVal, valSize, currType);
        
        if (!newNode)
        {
            printf("Error insertUpdate() node initial fail\n");
            return ERR_INITIAL_FAIL;
        }
        ListNode *tmp = ht->slot[index];
        
        if (tmp)
        {
            ht->collision += 1;
        }
        ht->slot[index] = newNode;
        newNode->next = tmp;
        ht->dataCount += 1;
    }
    pos = 0;                                //if used search then reset pos before return
    return SUCCESS;
}

int delete(hashTable *ht, char *currKey)
{
    if (!ht)
    {
        printf("delData() hashTable  is null.\n");
        return ERR_NULL;
    }
    if(!currKey)
    {
        printf("delData() key is null.\n");
        return ERR_NULL;
    }
    int index = hashFunction(currKey);
    valDataType *searchReturn = search(ht, currKey);
    if (!searchReturn)                  //not found
    {
        printf("Error data not found can't delete.\n");
        return ERR_NOT_FOUND;
    }
    else
    {
        ListNode *target = ht->slot[index];
        if (pos == 0)                   //in the head
        {
            ht->slot[index] = target->next;
        }
        else                            //in the mid or tail
        {
            ListNode *targetPre = ht->slot[index];
            for (int i = 0; i < pos; i++)
            {
                target = target->next;
                if (i < pos - 1)
                    targetPre = targetPre->next;
            }
            targetPre->next = target->next;
        }
        free(target->val.data);        //delete data
        target->val.data = NULL;
        free(target);
        target = NULL;
        ht->dataCount -= 1;

        free(searchReturn->data);      //delete search return val
        searchReturn->data = NULL;
        free(searchReturn);
        searchReturn = NULL;
    }
    pos = 0;                            //if used search then reset pos before return
    return SUCCESS;
}

valDataType *search(hashTable *ht, char *currKey)
{
    pos=0;
    if (!ht)
    {
        printf("search() hashTable is null.\n");
        return NULL;
    }
    if(!currKey)
    {
        printf("search() key is null.\n");
        return NULL;
    }
    int index = hashFunction(currKey);   
    ListNode *ptr = ht->slot[index];
    if (!ptr)
    {
        return NULL;
    }
    while (ptr)
    {
        if (strncmp(ptr->key, currKey, max(strlen(ptr->key), strlen(currKey))) == 0) //check there is the same key in table
        {
            valDataType *rtVal=(valDataType *)malloc(sizeof(valDataType));
            if(!rtVal)
            {
                printf("Error search() rtval malloc fail\n");
                return NULL;
            }
            rtVal->data=(valDataType *)malloc(sizeof(char)*ptr->val.valSize);
            if(!rtVal->data)
            {
                printf("Error search() rtval->data malloc fail\n");
                return NULL;
            }
            rtVal->type=ptr->val.type;
            rtVal->valSize=ptr->val.valSize;
            memcpy(rtVal->data,ptr->val.data,ptr->val.valSize);
            return rtVal;
        }
        ptr = ptr->next;
        pos += 1;
    }
    return NULL;
}

int printVal(valDataType *currVal) 
{
    
    if (!currVal || !currVal->data)
    {
        printf("Error not found or data already deleted\n");
        return ERR_NOT_FOUND;
    }
    if (currVal->type == TYPE_INT)        //print int val
    {
        printf("%lld\n", *(long long int*)currVal->data);
    }
    else if (currVal->type == TYPE_STR)   //print str val
    {
        printf("%s\n",(char *)currVal->data);
    }
    else                                 //print binary val
    {
        for (int i=0;i<currVal->valSize-1;i++)
        {
            printf("0x%02X ", ((char*)currVal->data)[i]);
        }
        printf("\n");
    }
    return SUCCESS;
}

int destroyTable(hashTable *ht)
{
    if (!ht)
    {
        printf("Hash table is null can't destroy");
        return SUCCESS;
    }
    for (int i = 0; i < MAX_TABLE_SIZE; i++)
    {
        if (ht->slot[i] != NULL)
        {
            ListNode *ptr = ht->slot[i];
            while (ptr)
            {
                ListNode *ptrNext = ptr->next;
                free(ptr->val.data);
                free(ptr);
                ptr = ptrNext;
            }
        }
    }
    free(ht->slot);
    free(ht);
    return SUCCESS;
}

