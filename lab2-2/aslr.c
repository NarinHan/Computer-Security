#include <stdio.h>
#include <stdlib.h>

void main()
{
    char x[12];
    char *y = malloc(sizeof(char) * 12);

    printf("Address of buffer x (on stack): %p\n", x);
    printf("Address of buffer y (on heap) : %p\n", y);
}
