#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[100];
    gethostname(name, 100);
    
    if(strcmp(name, argv[1]) == 0) {
        printf("win\n");
    }
    else {
        printf("lose\n");
    }
}