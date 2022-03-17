#include<stdlib.h>
#include<stdio.h>
#include<time.h>
#define TOTAL 5
int password[TOTAL];

int Password(int MAX, int a)
{
    int i;

    srand(time(NULL));
    for (i=0;i<TOTAL;i++){
	    password[i]=(rand()%MAX);
            #ifdef DEBUG
                printf("No: %d, Password= %04d\n",i,password[i]);
            #endif
        
    }
    for (i=0;i<TOTAL;i++){
        if (a!=password[i])
            return 0;
    }
    return 1;
}

int main()
{
    int a;
    scanf("%d", &a);
    if (Password(10000, a))
        printf("good");
    else 
        printf("bad");
    return 0;
}
