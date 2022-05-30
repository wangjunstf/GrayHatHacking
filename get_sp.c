#include <stdio.h>

unsigned int get_sp(void){
    __asm__("movl %esp,%eax");
}

int main(){
    printf("Stack Pointer (ESP):0x%x\n",get_sp());
}
