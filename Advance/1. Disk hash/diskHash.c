#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include "diskHash.h"

#define SUCCESS                  0
#define ERR_BASE                -1
#define ERR_MALLOC_FAIL     ERR_BASE - 1
#define ERR_DUPLICAT        ERR_BASE - 2
#define ERR_NOT_FOUND       ERR_BASE - 3
#define ERR_EXPORT_FAIL     ERR_BASE - 4
#define ERR_IMPORT_FAIL     ERR_BASE - 5
#define ERR_OPEN_FAIL       ERR_BASE - 6
#define ERR_ARGUMENTS       ERR_BASE - 7
#define ERR_TYPE            ERR_BASE - 8 
#define ERR_TABLE_FULL      ERR_BASE - 9

#define MAX_VAL_LEN         4194304
#define MAX_ENTRIES         120910  
#define MAX_KEY_LEN         256     
#define SEED                0x12345678       //for hash function's begin hash value

#define max(a, b) ((a) > (b) ? (a) : (b))

int hash(char *currKey)
{
  unsigned int hash = SEED;
  while (*currKey != '\0')
      hash = 17000069 * hash + *currKey++;
  return hash % MAX_ENTRIES;
}

int insertUpdate(char *currKey, valType *currVal)
{
  printf("%s\n",currKey);
  FILE *index_file = fopen("Table_index.txt", "rb+");
  FILE *table_file = fopen("Hash_Table.txt", "rb+");

  if (!index_file || !table_file) 
  {
    printf("File open error");
    if (index_file) fclose(index_file);
    if (table_file) fclose(table_file);
    return ERR_OPEN_FAIL;
  }

  IndexEntry entry;
  int hashIndex = hash(currKey);
  int orgHashIndex = hashIndex;
  int foundDelEntry = 0;
  long delEntryPos = 0;

  fseek(index_file, hashIndex * sizeof(IndexEntry), SEEK_SET);

  while (1) 
  {
    fread(&entry, sizeof(IndexEntry), 1, index_file);
    if (entry.deleted == 1 && !foundDelEntry) 
    {
      foundDelEntry = 1;
      delEntryPos = ftell(index_file) - sizeof(IndexEntry);
    }

    if (strcmp(entry.key, "") == 0 || strcmp(entry.key, currKey) == 0) 
    {
      break;
    }

    hashIndex = (hashIndex + 1) % MAX_ENTRIES;
    fseek(index_file, hashIndex * sizeof(IndexEntry), SEEK_SET);

    if (hashIndex == orgHashIndex) 
    {
      // if looped back to the original position, the table is full
      printf("Hash table is full\n");
      fclose(index_file);
      fclose(table_file);
      return ERR_TABLE_FULL;
    }
  }
  int formerState = entry.deleted;
  if (strcmp(entry.key, currKey) == 0)
  {
    entry.deleted = 0;
    char *oldValue = (char *)malloc(entry.length);
    if (!oldValue) 
    {
      printf("Error malloc failed\n");
      fclose(index_file);
      fclose(table_file);
      return ERR_MALLOC_FAIL;
    }

    fseek(table_file, entry.offset, SEEK_SET);
    fread(oldValue, sizeof(char), entry.length, table_file);

    // Key exists, check if value needs to be updated
    if (entry.length == currVal->valSize && entry.type == currVal->type && memcmp(oldValue, currVal->data, entry.length) == 0) 
    {
      // Value is the same, no update needed
      free(oldValue);
      if(formerState == 0)
      {
        printf("Duplicat don't need to insert %s.\n" ,currKey);
        fclose(index_file);
        fclose(table_file);
        return ERR_DUPLICAT;
      }

      fseek(index_file, hashIndex * sizeof(IndexEntry), SEEK_SET);
      fwrite(&entry, sizeof(IndexEntry), 1, index_file);
      fclose(index_file);
      fclose(table_file);
      return SUCCESS;
    } 
    else 
    {
      // Value length or type changed, update offset and length to the end of file
      printf("update val\n");
      fseek(table_file, 0, SEEK_END);
      entry.offset = ftell(table_file);
      entry.length = currVal->valSize;
      entry.type = currVal->type;
    }
    free(oldValue);
  } 
  else
  {
    // New key, use the found deleted entry position if available
    if (foundDelEntry) 
    {
      fseek(index_file, delEntryPos, SEEK_SET);
    } 
    else 
    {
      fseek(index_file, hashIndex * sizeof(IndexEntry), SEEK_SET);
    }

    fseek(table_file, 0, SEEK_END);
    entry.offset = ftell(table_file);
    strncpy(entry.key, currKey, strlen(currKey)+1);
    entry.key[strlen(currKey)] = '\0'; 
    entry.length = currVal->valSize;
    entry.type = currVal->type;
    entry.deleted = 0;
  }

  // Write the new or updated value to the table file
  fwrite(currVal->data, sizeof(char), currVal->valSize, table_file);

  // Update the index file
  fseek(index_file, hashIndex * sizeof(IndexEntry), SEEK_SET);
  fwrite(&entry, sizeof(IndexEntry), 1, index_file);

  fclose(index_file);
  fclose(table_file);

  return SUCCESS;
}

int del(char *currKey)
{
  FILE *index_file = fopen("Table_index.txt", "rb+");
  if (!index_file)
  {
    printf("Index file open error");
    return ERR_OPEN_FAIL;
  }

  IndexEntry entry;
  unsigned int hash_index = hash(currKey);
  fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);

  while (1) 
  {
    fread(&entry, sizeof(IndexEntry), 1, index_file);
    if (strcmp(entry.key, currKey) == 0 && entry.deleted!=1) 
    {
      entry.deleted = 1; // Mark as deleted
      fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);
      fwrite(&entry, sizeof(IndexEntry), 1, index_file);
      break;
    }

    if (strcmp(entry.key, "") == 0 || entry.deleted == 1) 
    {
      if(entry.deleted)printf("deleted before. FAILUER\n");
      else printf("Key not found. FAILUER\n");
      return ERR_NOT_FOUND;
    }
    
    hash_index = (hash_index + 1) % MAX_ENTRIES;
    fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);
  }

  fclose(index_file);
  printf("Successfully delete %s\n" ,currKey);
  return SUCCESS;
}

int query(char *currKey)
{
  FILE *index_file = fopen("Table_index.txt", "rb");
  FILE *table_file = fopen("Hash_Table.txt", "rb");
  if (!index_file || !table_file) 
  {
    printf("File open error\n");
    if(table_file) fclose(table_file);
    if(index_file) fclose(index_file);
    return ERR_OPEN_FAIL;
  }

  IndexEntry entry;
  unsigned int hash_index = hash(currKey);
  fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);

  while (1) 
  {
    fread(&entry, sizeof(IndexEntry), 1, index_file);
    if (strcmp(entry.key, currKey) == 0 && entry.deleted == 0) 
    {
      fseek(table_file, entry.offset, SEEK_SET);
      char *value = (char *)malloc(entry.length);
      fread(value, sizeof(char), entry.length, table_file);
      printf("Value for key %s: ", currKey);
      if (entry.type == TYPE_INT) 
      {
          printf("%d\n", *(int *)value);
      } 
      else if (entry.type == TYPE_STR) 
      {
          printf("%s \n", value);
      } 
      else if (entry.type == TYPE_BINARY) 
      {
          for (size_t i = 0; i < entry.length; i++) 
          {
              printf("0x%02X ", (unsigned char)value[i]);
          }
          printf("\n");
      }
      free(value);
      break;
    }

    if (strcmp(entry.key, "") == 0 || entry.deleted == 1) 
    {
      printf("Key not found\n");
      break;
    }

    hash_index = (hash_index + 1) % MAX_ENTRIES;
    fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);
  }

  fclose(index_file);
  fclose(table_file);
  return SUCCESS;
}

int importFile(char *fileName, char *fileType)
{
  TYPE fType;
  if(strncmp(fileType, "str", 4) == 0) fType = TYPE_STR;
  else if(strncmp(fileType, "binary", 7) == 0) fType = TYPE_BINARY;
  else
  {
    printf("Import file type error.\n");
    return ERR_TYPE;
  }

  FILE *import_file;
  if (fType == TYPE_BINARY) 
  {
    import_file = fopen(fileName, "rb");
    if (!import_file) 
    {
      printf("Error open import file fail\n");
      return ERR_OPEN_FAIL;
    }
  } 
  else 
  {
      import_file = fopen(fileName, "r");
      if (!import_file) 
      {
        printf("Error open import file fail\n");
        return ERR_OPEN_FAIL;
      }
  }

  char tmp[MAX_VAL_LEN];
  fseek(import_file, 0, SEEK_END);
  long fileLen = ftell(import_file);
  fseek(import_file, 0, SEEK_SET);
  fread(tmp, sizeof(char), fileLen, import_file);
  if (fType == TYPE_STR) 
  {
    tmp[fileLen] = '\0';
  }

  char *key = fileName;
  valType val;
  val.type = fType;
  val.data = tmp;
  val.valSize = fileLen + (fType == TYPE_STR ? 1 : 0);
  int rc = insertUpdate(key, &val);
  if (rc == SUCCESS) 
  {
      printf("Ok %s %ld\n", fileName, fileLen);
      fclose(import_file);
      return SUCCESS;
  }

  printf("FAILURE\n");
  fclose(import_file);
  return ERR_IMPORT_FAIL;
 
}

int exportFile(char *currkey, char *fileName)
{
  FILE *out_file = fopen(fileName, "w");
  FILE *index_file = fopen("Table_index.txt", "rb");
  if (!index_file || !out_file) 
  { 
    perror("File open error not found");
    if (index_file) fclose(index_file);
    if (out_file) fclose(out_file);
    return ERR_OPEN_FAIL;
  }

  IndexEntry entry;
  unsigned int hash_index = hash(currkey);
  fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);

  while (1) 
  {
    fread(&entry, sizeof(IndexEntry), 1, index_file);
    if (strcmp(entry.key, currkey) == 0 && entry.deleted == 0) 
    {
      FILE *table_file = fopen("Hash_Table.txt", "rb");
      if (!table_file) 
      {
        perror("Table file open error");
        fclose(out_file);
        fclose(index_file);
        return ERR_OPEN_FAIL;
      }

      fseek(table_file, entry.offset, SEEK_SET);
      char *value = (char *)malloc(entry.length);
      if (!value) 
      {
        perror("Memory allocation error");
        fclose(out_file);
        fclose(index_file);
        fclose(table_file);
        return ERR_MALLOC_FAIL;
      }

      fread(value, sizeof(char), entry.length, table_file);

      if (entry.type == TYPE_INT) 
      {
        fprintf(out_file, "%d\n", *(int *)value);
      } 

      else if (entry.type == TYPE_STR) 
      {
        fprintf(out_file, "%s\n", value);
      } 
      
      else if (entry.type == TYPE_BINARY) 
      {
        fwrite(value, sizeof(char), entry.length, out_file);
      }

      free(value);
      fclose(table_file);
      break;
    }

    if (strcmp(entry.key, "") == 0) 
    {
      printf("Key not found\n");
      break;
    }

    hash_index = (hash_index + 1) % MAX_ENTRIES;
    fseek(index_file, hash_index * sizeof(IndexEntry), SEEK_SET);
  }

  printf("OK %s %ld\n", fileName, ftell(out_file));
  fclose(index_file);
  fclose(out_file);

  return SUCCESS;
}


int add(char *fileName)
{
  FILE *add_file = fopen(fileName, "r");
  if(!add_file)
  {
    printf("add_file  open error\n");
    return ERR_OPEN_FAIL;
  }
  int count = 0;
  valType val;
  val.type = TYPE_STR;
  char tmp[MAX_VAL_LEN];
  char key[MAX_KEY_LEN];
  char *startPos = tmp;

  while(fscanf(add_file,"%s\t%[^\n]",key,tmp) != EOF)
  {
    val.data = &tmp;
    val.valSize = strlen(tmp) + 1;
    int rc = insertUpdate(key,&val);
    if(rc == SUCCESS) count += 1;
  }
  printf("Ok %d\n",count);
  
  return SUCCESS;
}

int resetTable()
{
  FILE *index_file = fopen("Table_index.txt", "rb+");
  FILE *table_file = fopen("Hash_Table.txt", "rb");
  FILE *temp_table_file = fopen("Tmp_Table.txt", "wb");
  if (!index_file || !table_file||!temp_table_file) {
      printf("File open error\n");
      if (index_file) fclose(index_file);
      if (table_file) fclose(table_file);
      if(temp_table_file) fclose(temp_table_file);
      return ERR_OPEN_FAIL;
  }

  IndexEntry entry;
  long newOffset = 0;

  while(fread(&entry, sizeof(IndexEntry), 1, index_file) == 1)
  {
    if(entry.deleted == 0 && strcmp(entry.key,"") != 0)
    {
      char *data = (char *)malloc(entry.length);
      if (!data) 
      {
        printf("Error malloc failed\n");
        fclose(index_file);
        fclose(table_file);
        fclose(temp_table_file);
        remove("Tmp_Table.txt");
        return ERR_MALLOC_FAIL;
      }
      //move data to new file
      fseek(table_file, entry.offset, SEEK_SET);
      fread(data,sizeof(char),entry.length,table_file);

      fseek(temp_table_file,newOffset,SEEK_SET);
      fwrite(data,sizeof(char),entry.length,temp_table_file);
     
      //update entry.off
      entry.offset = newOffset;
      newOffset += entry.length;
      fseek(index_file, -sizeof(IndexEntry), SEEK_CUR);
      fwrite(&entry, sizeof(IndexEntry), 1, index_file);

      free(data); 
    }
    else
    {
      memset(&entry, 0, sizeof(IndexEntry));
      fseek(index_file, -sizeof(IndexEntry), SEEK_CUR);
      fwrite(&entry, sizeof(IndexEntry), 1, index_file);
    }
  }

  fclose(index_file);
  fclose(table_file);
  fclose(temp_table_file);

  remove("Hash_Table.txt");
  rename("Tmp_Table.txt","Hash_Table.txt");
}
