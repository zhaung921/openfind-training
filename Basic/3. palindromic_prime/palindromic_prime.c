#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<math.h>

#define SUCCESS     0
#define ERR_BASE    0
#define ERR_INPUT_ERROR         ERR_BASE-1
#define ERR_INPUT_OUT_OF_RANGE  ERR_BASE-2
#define ERR_NOT_FOUND           ERR_BASE-3
#define ERR_NULL_PTR            ERR_BASE-4

#define MAX_SIZE        100000000
#define MAX_DIGIT           8
#define TOW_DIG_EXCEP       11
#define TOW_DIG_BOUND       10
#define ONE_DIG_EXCEP_1     2    
#define ONE_DIG_EXCEP_2     5

int count=0;

bool isPrime(int num) 
{
    if (num < 2 || num % 2 == 0) return num == 2;
    int limit = sqrt(num);//set limit for only checking untill sqrt(num)
    for (int i = 3; i <= limit; i++) 
    {
        if (num % i == 0) return false;
    }
    return true;
}

int strrev(char * str)
{
    if (!str || !*str) 
    {
        printf("strrev() str is null\n");
        return ERR_NULL_PTR;
    }
    int left=0;
    int right=strlen(str)-1;
    while (left < right)
    {  
        char tempChar = str[left];
        str[left] = str[right];
        str[right] = tempChar;
        left++;
        right--;
    }
    return SUCCESS;
}

int findPalinPrime(int input)
{
    if(input<10)
    {
        for(int i=2;i<=input;i++)
        {
            if(isPrime(i))
            {
                printf("%d ",i);
                count++;
            }
        }
        printf("\n");
        return SUCCESS;
    }
    else
    {
        int palNum=0;
        int i=1;
        while(palNum<=input) 
        {
            int dig=log10(i)+1;
            int lead=i/pow(10,dig-1);
            if((lead%ONE_DIG_EXCEP_1==0&&i!=ONE_DIG_EXCEP_1)||(lead==ONE_DIG_EXCEP_2&&i!=ONE_DIG_EXCEP_2))
            {
                i+=pow(10,dig-1);
            }
            else
            {
                if(i==TOW_DIG_BOUND)
                {
                    printf("%d ",TOW_DIG_EXCEP);
                    count+=1;
                }
                if(isPrime(palNum))
                {
                    printf("%d ",palNum);
                    count++;
                } 
                char head[MAX_DIGIT+1], tail[MAX_DIGIT+1];              //creat palindromic number and also odd
                sprintf(head, "%d", i);
                strncpy(tail, head, strlen(head)+1);
                strrev(tail);
                palNum = atoi(strncat(head, tail + 1,strlen(tail)));    //creat palindromic number and also odd
                i++;
            }
        }   
        printf("\n");
    }
    return SUCCESS;
}


int main(int argc,char* argv[])
{
    if(argc<2)
    {
        printf("Input error\n");
        return ERR_INPUT_ERROR;
    }
    int input=atoi(argv[1]);
    if(input>MAX_SIZE||input<=1)
    {
        printf("Input number out of range\n");
        return ERR_INPUT_OUT_OF_RANGE;
    }
    
    if(findPalinPrime(input)!=SUCCESS)
    {
        printf("No any palindromic prime exist\n");
        return ERR_NOT_FOUND;
    }
    
    printf("%s %d\n","Count:",count);
    
    return SUCCESS;
}