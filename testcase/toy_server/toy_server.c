#include<stdlib.h>
#include<stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[100];
    while (1)
    {
        memset(buf, 0, sizeof(buf));
        scanf("%s",buf);
        if (!(strncmp(buf, "hello", 5))){
            printf("Hello World!\n");
        } else if (!(strncmp(buf, "help", 4))){
            printf("help service started...\n");
            int level;
            scanf("%d", &level);
            if (level>0)
                printf("Call 911\n");
            else 
                printf("No Worry!\n");
        } else {
            printf("No such commond\n");
        }
    }
    return 0;
}