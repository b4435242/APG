#include<stdlib.h>
#include<stdio.h>
#include <string.h>

void fire(){
    printf("Call 911\n");
}

void fine(){
    printf("No Worry!\n");
}

int key(){
    int k;
    scanf("%d", &k);
    return k;
}

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
            int level = key();
            if (level > 0)
                fire();
            else 
                fine();
        } else {
            printf("No such commond\n");
        }
    }
    return 0;
}