#include <stdio.h>
#include <stdlib.h>

int main(void){
    printf("Hello\n");

    // pointer example
    int x = 10;
    int *p = &x;

    printf("%d\n", x);           // the value of x
    printf("%p\n", (void *)&x); // the address of x
    printf("%d\n", *p);          // the value stored by the pointer
    printf("%p\n", (void *)p);  // the address stored in the pointer


    //dangling pointer
    int * p = malloc(sizeof(int));
    free(p);
    //*p = 10;  -. wrong
    p = NULL;


    //malloc
    int * p = malloc(5 * sizeof(int));
    if ( p ==NULL){
        printd(" Memory allocation failed\n");
    }
    for(int i = 0 ; i< 5 ; i++){
        p[i] = i+ 1;
    }
    for( int  i=0;i<5 ; i++){
        printf("%d" ,p[i]);
    }
    free(p);
    return 0;
}