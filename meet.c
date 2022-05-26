#include <stdio.h>
#include <string.h>

int greeting(char *temp2){
    char name[400];
    strcpy(name,temp2);
    printf("Hello %s\n",name);
    return 0;
}

int main(int argc, char* argv[]){
    greeting(argv[1]);
    return 0;
}



