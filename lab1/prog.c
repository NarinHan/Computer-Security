/* prog.c */
#include <stdio.h>
#include <stdlib.h>

int main(void){    
    char arr[64];    
    char *ptr;    
    ptr = getenv("PWD");    
    if(ptr != NULL) {        
        sprintf(arr, "Present working directory is: %s", ptr);        
        printf("%s\n", arr);    
    }    
    return 0;
}

