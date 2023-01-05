#include <stdio.h>
#include <string.h>



int main(void){
    
    //char test[8] = "hello";
    char cpy[20];
    char input_string[100];

    
    read(0, input_string, 100);
    strcpy(cpy, input_string);
    //strncpy(cpy, input_string,100);
    printf("%s", cpy);

    return 0;
}
