/* This program has a buffer overflow vulnerability. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int foo(char *str)
{
    char buffer[10];

    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    foo(argv[1]);

    printf("Returned Properly\n");
    return 1;
}
