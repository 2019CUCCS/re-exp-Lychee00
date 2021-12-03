#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void Attack(){
    printf("Attacked!");
    system("C:\\Windows\\System32\\calc.exe");   
}

void fun(){
    char password[6]="ABCDE";
    char str[6];
    FILE *fp;
    if(!(fp=fopen("password.txt","r"))){
        exit(0);
    }
    fscanf(fp,"%s",str);

    str[5]='\0';
    if(strcmp(str,password)==0)
        printf("OK.\n");
    else
        printf("NO.\n");
}

int main(){
    fun();
    return 0;
}










