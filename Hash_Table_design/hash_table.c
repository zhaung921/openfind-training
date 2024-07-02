#include <stdio.h>
#include <stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<math.h>

#define SUCCESS                 -1
#define ERR_BASE                -1
#define ERR_MALLOC_FAIL       ERR_BASE-1    
#define ERR_EXIST             ERR_BASE-2
#define ERR_NULL              ERR_BASE-3
#define ERR_NOT_FOUND         ERR_BASE-4
#define ERR_OPEN_FAIL         ERR_BASE-5
#define ERR_OUT_OF_RANGE      ERR_BASE-6
#define ERR_DUL               ERR_BASE-7

#define MAX_TABLE_SIZE         120910 //90700
#define MAX_KEY_LEN            255
#define SEED                   0x12345678

#define max(a, b) ((a) > (b) ? (a) : (b))

int collision=0;
int numsInsert=0;

typedef struct htListNode
{
    char key[MAX_KEY_LEN+1];
    int val;
    struct htListNode* next;
}htListNode;

typedef struct hashTable
{
    htListNode** list;
    int size;
    int count;
}hashTable;

htListNode* initNode(char* ikey,int ival)// initial a new node
{
    htListNode* item=(htListNode*)malloc(sizeof(htListNode));
    if(!item)
    {
        printf("%s","Error initNode() malloc fail.\n");
        return NULL;
    }
    item->next=NULL;
    strncpy(item->key,ikey,strlen(ikey));//set keys
    item->key[strlen(ikey)+1]='\0';
    item->val=ival;
    return item;
}

hashTable* initHash(int iSize)//initial hashtable
{  
    hashTable* table = (hashTable*) malloc(sizeof(hashTable));
    if(!table)
    { 
        printf("%s","Error initHash() malloc fail.\n");
        return NULL;
    }
    table->size = iSize;
    table->count = 0;
    table->list = (htListNode**) calloc(table->size, sizeof(htListNode*));
    if(!table->list)
    { 
        printf("%s","Error initHash() malloc fail.\n");
        return NULL;
    }

    for (int i = 0; i < table->size; i++)
        table->list[i] = NULL;
    
    
    return table;   
}
int findUpdate(hashTable* ht,int index,char*ikey,int ival)//find if data duplicate or update key->val
{
    if(!ht)
    {
        printf("load() hashTable is null.\n");
        return ERR_NULL;
    }
    htListNode* ptr=ht->list[index];
    if(!ptr)
    {
        return ERR_NOT_FOUND;
    }
    while(ptr)
    {
        if(strncmp(ptr->key,ikey,max(strlen(ptr->key),strlen(ikey)))==0)//check there is the same key in table
        {
            if(ptr->val==ival)//if the val is the same
            {
                printf("%s %s %d\n","Repeat data",ptr->key,ptr->val);
                return ERR_DUL;
            }
            else//update key's val
            {
                ptr->val=ival;
                return SUCCESS;
            }
        }
        ptr=ptr->next;
    }
    return ERR_NOT_FOUND;
    
}
int insertLT(hashTable* ht,int index,char*ikey,int ival)//insert data into table and collision handling
{
    if(!ht)
    {
        printf("load() hashTable is null.\n");
        return ERR_NULL;
    }
    
    htListNode* node=initNode(ikey,ival);
    if(!node)
    {
        printf("%s","Error insertLT() node malloc fail\n");
        return ERR_MALLOC_FAIL;
    }
    htListNode* tmp=ht->list[index];//visit slot
    if(tmp) //if tmp not null means collision
    {
        collision+=1;
    }
    //inserting list head
    ht->list[index]=node;
    node->next=tmp;
    ht->count+=1;
    
    return SUCCESS;
}


int hashFunction(char* ikey)//large prime
{
    unsigned int hash=SEED;
    while (*ikey != '\0')
        hash = 17000069*hash + *ikey++;

    return hash%MAX_TABLE_SIZE;   
}
    
int build_hash(hashTable* ht,char* ikey,int ival)
{
    if(!ht)
    {
        printf("load() hashTable is null.\n");
        return ERR_NULL;
    }
    int index=hashFunction(ikey);//get hash value
    if(findUpdate(ht,index,ikey,ival)==ERR_NOT_FOUND)
    {
        insertLT(ht,index,ikey,ival);
        numsInsert+=1;
    }
    return SUCCESS;
}
int query_hash(hashTable* ht,char* ikey)//return key's value if key in table
{
    if(!ht)
    {
        printf("load() hashTable is null.\n");
        return ERR_NULL;
    }
    if(!ikey)
    {
        printf("%s","Error query_hash() input is null");
        return ERR_NULL;
    }
    
    int index=hashFunction(ikey);
    htListNode* ptr=ht->list[index];
    while(ptr)
    {
        if(strncmp(ptr->key,ikey,max(strlen(ptr->key),strlen(ikey)))==0)
        {
            return ptr->val;
        }
        ptr=ptr->next;
    }
    printf("%s %s",ikey,"not in table.\n");
    return ERR_NOT_FOUND;
}

int load(char* filename,hashTable *ht)
{
    if(!ht)
    {
        printf("load() hashTable is null.\n");
        return ERR_NULL;
    }
    FILE *fp  = fopen(filename, "r"); 
    if(fp==NULL)
    {
        printf("Error opening the file %s", filename);
        return ERR_OPEN_FAIL;
    }
    char key[MAX_KEY_LEN+1];
    int val=0;
    while (fscanf(fp,"%s %d\n",key,&val)!=EOF)
    {  
        int msg=build_hash(ht,key,val);
        if(msg!=SUCCESS)
        {
            return msg;
        } 
    }
    fclose (fp);   
    return SUCCESS;  
}
int main()
{
    int size=MAX_TABLE_SIZE;
    hashTable* ht=initHash(size);
    if(!ht)
    {
        printf("%s","Error initHash()  fail.\n");
        return ERR_MALLOC_FAIL;
    }
    int msg=load("dict.txt",ht);
    if(msg!=SUCCESS)
    {
        printf("%s %d\n","LOAD ERROR MESSAGE:",msg);
        return msg;
    }

    float loadFac=(float)ht->count/ht->size;
    int expColl=numsInsert - MAX_TABLE_SIZE * (1 - pow((double)(MAX_TABLE_SIZE - 1) / MAX_TABLE_SIZE, numsInsert));
    ///printf("%s %d\n","count:",ht->count);
    printf("\n%s %lf\n","Load Factor:",loadFac*100);
    printf("%s %d\n","Expect collisions :",expColl);
    printf("%s %d\n","Real collision:",collision);

    
    printf("%d\n",query_hash(ht,"worshipping"));
    printf("%d\n",query_hash(ht,"wrapping"));
    printf("%d\n",query_hash(ht,"cuticula"));
    printf("%d\n",query_hash(ht,"zip"));
    
    return SUCCESS;
}
