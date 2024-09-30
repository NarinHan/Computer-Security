#include <stdio.h>
#include <stdlib.h>
int main()
{
    char *badstring = (char *)getenv("MYSTRING");
    if (badstring) {
        printf("  Value:   %s\n", badstring);
        printf("  Address: %p\n", badstring);
    }
    return 1;
}

