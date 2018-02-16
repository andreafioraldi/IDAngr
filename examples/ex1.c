#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *encrypt(char *arr, int len, char add)
{
    int i;
    char *res = malloc(len);
    for(i = 0; i < len; ++i)
    {
        res[i] = arr[i] + add;
    }
    return res;
}

int hash(char *arr, int len)
{
    int acc = 0;
    int i;
    for(i = 0; i < len; ++i)
        acc += arr[i];
    return acc;
}

int main()
{
    printf("Insert key: ");
    char read[100];
    fgets(read, 100, stdin);
    int len = strlen(read);
    char *encr = encrypt(read, len, 10);
    int h = hash(encr, len);
    
    if(h == 462)
        printf("Win\n");
    else
        printf("Fail\n");
}
