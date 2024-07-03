#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>

#define SUCCESS                     0
#define ERR_BASE                    0
#define ERR_OPEN_FAIL           ERR_BASE-1
#define ERR_SAVE_FAIL           ERR_BASE-3
#define ERR_MALLOC_FAIL         ERR_BASE-4
#define ERR_INSUFFICIENT_ARGS   ERR_BASE-5

#define MAX_STR_NUMBRE            1000000
#define MAX_STR_LEN                127
int count = 0;

typedef struct {
    char str[MAX_STR_LEN];
    int val;
}Data;

int compareData(const void *a, const void *b) {
    return ((Data *)b)->val - ((Data *)a)->val;
}

int main(int argc, char *argv[])
{
    if(argc<3)
    {
         printf("Usage: %s [input filename] [output filename]\n", argv[0]);
         return ERR_INSUFFICIENT_ARGS;
    }
    char* inputFile = argv[1];
    char* outputFile = argv[2];

    FILE *fp  = fopen(inputFile, "r");
    if (fp == NULL)
    {
        printf("Error opening the file %s", inputFile);
        return ERR_OPEN_FAIL;
    }

    Data *userData = (Data *)malloc(sizeof(Data)*MAX_STR_NUMBRE);
    if(!userData)
    {
        printf("userData malloc fail.\n");
        return ERR_MALLOC_FAIL;
    }

    int i=0;
    while (fscanf(fp,"%s\t%d\n",userData[i].str,&userData[i].val)!=EOF)
    {  
        count++;
        i++;  
    }

    qsort(userData, count, sizeof(Data),compareData);        //quicksort 

    FILE *fp2 = fopen(outputFile, "w"); 
    if (fp2 == NULL)
    {
        printf("Error opening the file %s", outputFile);
        return ERR_OPEN_FAIL;
    }

    char buffer[BUFSIZ*1010];                               //creat large buffer for reducing I/O
    setvbuf(fp2, buffer, _IOFBF, sizeof(buffer));           //set buffer mode it will call I/O when buffer full

    for(int i=0;i<count;i++)
    {
        fprintf(fp2, "%s %d\n", userData[i].str, userData[i].val);
    }

    fclose(fp);  
    fclose(fp2);
    free(userData);
    return SUCCESS;                                       
}
