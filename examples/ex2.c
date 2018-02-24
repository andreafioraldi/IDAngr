#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

void foo(void);
int change_page_permissions_of_address(void *addr);

//http://shell-storm.org/shellcode/files/shellcode-878.php
char shellcode[] = "\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41";

int main(void) {
    void *foo_addr = (void*)foo;

    if(change_page_permissions_of_address(foo_addr) == -1) {
        fprintf(stderr, "Error while changing page permissions of foo(): %s\n", strerror(errno));
        return 1;
    }

    puts("calling original foo...");
    foo();

    memcpy(foo_addr, shellcode, sizeof(shellcode));

    puts("calling modifed foo...");
    foo();

    return 0;
}

void foo(void) {
    printf("\n.~~~~.\ni====i_\n|cccc|_)\n|cccc|   hjw\n`-==-'\n\n");
}

int change_page_permissions_of_address(void *addr) {
    // Move the pointer to the page boundary
    int page_size = getpagesize();
    addr -= (unsigned long)addr % page_size;

    if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return -1;
    }

    return 0;
}
