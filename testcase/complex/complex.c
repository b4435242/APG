#include<stdlib.h>
#include<stdio.h>

int main(int argc, char *argv[])
{
    asm("nop"); // 0x400575
    char input[30] = "C8763";
    //scanf("%s", &input);
    //char *input = argv[1];

    /*int encrypted[200] = { 0x8e, 0x41, 0xb1, 0xdc, 0x76, 0x4e, 0xf9, 0xc8, 0x84, 0x42,
                           0x52, 0xd4, 0x7e, 0x43, 0xf1, 0x39, 0x58, 0x2e, 0x29, 0x88,
                           0xb6, 0x35, 0x11, 0x8c, 0x5e, 0x62, 0x19, 0xb8, 0x5c, 0x36,
                           0xf2, 0xa4, 0x36, 0x1f, 0x90, 0x89, 0x40, 0x1a, 0x88, 0x58,
                           0xde, 0x19, 0xf0, 0x7c, 0x46, 0x76, 0xb8, 0x68, 0x14, 0x0a,
                           0x93, 0x34, 0x0e, 0x0b, 0x30, 0xd9, 0x08, 0x16, 0x68, 0x28,
                           0x106,0x0d, 0x50, 0x2c, 0xee, 0x0a, 0xdb, 0xd9, 0xec, 0x7e,
                           0x30, 0x105,0x106,0x87, 0xd3, 0x28, 0xf0, 0x82, 0xcb, 0xf9,
                           0x2e, 0x71, 0x33, 0x9d, 0xd6, 0x1e, 0x7b, 0x89, 0xe4, 0x72,
                           0xd0, 0x95, 0xde, 0x73, 0x73, 0x78, 0xb8, 0x5e, 0xaa, 0x49,
                           0x56, 0x65, 0x92, 0x4d, 0xbe, 0x32, 0x9a, 0x79, 0xbc, 0x66,
                           0x71, 0x65, 0x96, 0x4f, 0x12, 0xc8, 0xa0, 0x4a, 0x0a, 0x19,
                           0x7e, 0x49, 0x72, 0x3d, 0xa6, 0x46, 0x3a, 0x29, 0x75, 0xba,
                           0x16, 0xf6, 0x6f, 0xbb, 0xb5, 0x1b, 0x69, 0xc6, 0xed, 0xea,
                           0xa7, 0xbd, 0xd5, 0xee, 0x4f, 0xda, 0x5d, 0x9a, 0x4d, 0xae,
                           0xb6, 0xc6, 0x67, 0xb7, 0x55, 0x6b, 0x51, 0xb2, 0x4d, 0xba,
                           0xcf, 0xa1, 0xb4, 0x5e, 0x37, 0xee, 0xfc, 0x4a, 0x45, 0xa2,
                           0x57, 0x56, 0x3f, 0xa3, 0xf4, 0xbb, 0x19, 0x8e, 0x2c, 0x0a,
                           0xf7, 0x95, 0x14, 0x0e, 0x1f, 0x102,0x1c, 0x3a, 0x1d, 0x96,
                           0xf7, 0x26, 0xf7, 0xff, 0x97, 0x0a, 0x101,0xfa, 0x8f, 0xdb};*/
    int encrypted[30] = { 0x8e , 0x41 , 0xb1 , 0xdc, 0x76, 0x4e , 0xf9 , 0xc8 , 0x84, 0x42,
                          0x52 , 0xd4 , 0x7e , 0x43, 0xf1, 0x39 , 0x58 , 0x2e , 0x29, 0x88,
                          0xb6 , 0x35 , 0x11 , 0x8c, 0x5e, 0x62 , 0x19 , 0xb8 , 0x5c, 0x36 };

    int target = 0; 
    asm("nop"); // 0x4005b4
    for(int i = 0; i < 30; i++){
        int num1 = ((input[i] ^ i) << ((i ^ 9) & 3)) % 0x100;
        int num2 = ((input[i] ^ i) >> (8 - ((i ^ 9) & 3))) % 0x100;
        int num = (num1 | num2) % 0x100;
        int pass = num + 0x8;
        /*printf("%x\n", pass);
        if(i%10 == 9)
            printf("\n");*/
        if( encrypted[i] != (num+8) )
            break;
        if(i == 29)  
            target = 1;
    }
    if(target)
        printf("You got it!!\n"); // 0x400682
    else
        printf("You failed!! Please try again\n"); // 0x400690
    return 0; // 4006af
}