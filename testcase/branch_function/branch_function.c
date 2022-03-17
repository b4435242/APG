#include<stdlib.h>
#include<stdio.h>

void test(int a, int b)
{
    if(a == 0x20 && b == 0x30){
        printf("target!!\n");
    }
    else{
        printf("fail!!\n");
    }
}


int main(int argc, char** argv)
{
    int a = 0, b = 0;
    asm("nop");

    test(a, b);
    return 0;
}
