#include<stdlib.h>
#include<stdio.h>

int main(int argc, char** argv)
{
    int a = 0x10, b = 0x20;
    //asm("nop");

    if (a == 0x11 && b == 0x21){
        printf("traget\n");
    }
    else{
        printf("fail\n");
    }
    return 0;
}
