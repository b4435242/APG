#include<stdlib.h>
#include<stdio.h>
#include<time.h>
#define TOTAL 5

Password(int MAX)
{
	int password[TOTAL];
    int i;

    srand(time(NULL));
    for (i=1;i<=TOTAL;i++){
	    password[i]=(rand()%MAX);
            #ifdef DEBUG
                printf("No: %d, Password= %04d\n",i,password[i]);
            #endif
    }
}

main()
{
    Password(10000);
    int a;
    scanf("%d", &a);
}
