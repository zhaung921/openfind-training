#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define ADD                 "add"
#define QUERY               "query"
#define DEL                 "del"
#define IMPORT              "import"
#define EXPORT              "export"
#define RESET_TABLE         "reset"

int main(int argc, char *argv[]) 
{
    if(argc<2)
    {
        printf("Error: Incorrect number of arguments.\n");
        return ERR_ARGUMENTS;
    }
    char *action = argv[1];
    
    if(strncmp(action, ADD, 4) == 0)
    {
        if(argc<3)
        {
            printf("Error: Incorrect number of arguments.\n");
            return ERR_ARGUMENTS;
        }
        char *fileName = argv[2];
        add(fileName);
    }
    else if(strncmp(action, QUERY, 6) == 0)
    {
        if(argc<3)
        {
            printf("Error: Incorrect number of arguments.\n");
            return ERR_ARGUMENTS;
        }
        char *key = argv[2];
        query(key);
    }
    else if(strncmp(action, DEL, 4) == 0)
    {
        if(argc<3)
        {
            printf("Error: Incorrect number of arguments.\n");
            return ERR_ARGUMENTS;
        }
        char *key = argv[2];
        del(key);
    }
    else if(strncmp(action, IMPORT, 7) == 0)
    {
        if(argc<4)
        {
            printf("Error: Incorrect number of arguments.\n");
            return ERR_ARGUMENTS;
        }
        char *fileName = argv[2];
        char *fileType = argv[3];
        importFile(fileName,fileType);
    }
    else if(strncmp(action, EXPORT, 7) == 0)
    {
        if(argc<4)
        {
            printf("Error: Incorrect number of arguments.\n");
            return ERR_ARGUMENTS;
        }
        char *key = argv[2];
        char *fileName = argv[3];
        exportFile(key, fileName);
    }
    else if(strncmp(action, RESET_TABLE, 6) == 0)
    {
        printf("Reset hash table to clear deleted data and old data....\n");
        resetTable();
        printf("Reset finsh.\n");
    }
    else
    {
        printf("Error: Incorrect  arguments. Using add [filename] ,query [key] ,del [key] ,import [filename] ,export [key] [save filename] , reset\n");
        return ERR_ARGUMENTS;

    }

    return SUCCESS;
}
