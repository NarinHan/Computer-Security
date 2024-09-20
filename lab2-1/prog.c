#include <stdio.h>
#include <stdlib.h>

int func(int a, int b)
{
    return (a + b) + (a - b);
}

int main()
{
    int a = 2, b = 4;
    static int x;
    int *ptr = (int *) malloc(2 * sizeof(int));
    
    ptr[0] = 5;
    ptr[1] = 6;

    x = ptr[0] + ptr[1]; 
    b = func(a, b);

    printf("b=%d, x=%d\n", b, x);   

    free(ptr);

    return 1;

}


