/* This program has a buffer overflow vulnerability. */
//#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int func2(char *str)
{
    char buffer[30];

    /* The following statement has 
       a buffer overflow problem */
    memcpy(buffer, str, 100);  

    return 1;
}

int func1(char *str) 
{
    return func2(str);
}

int main(int argc, char **argv)
{
    char str[400];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 300, badfile);
    func1(str);

    printf("Returned Properly\n");
    return 1;
}
