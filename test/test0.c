#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
//gcc test0.c -o test0 -lws2_32

int main(int argc, char **argv) {
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    WSAStartup(wVersionRequested, &wsaData);
    
    char name[100];
    gethostname(name, 100);
    
    if(strcmp(name, argv[1]) == 0) {
        printf("win\n");
    }
    else {
        printf("lose\n");
    }
}