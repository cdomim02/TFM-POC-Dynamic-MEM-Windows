#include <windows.h>
#include <stdio.h>

// Author: Carlos Dominguez
// Based on: https://github.com/B1TC0R3/double_free_vulnerability_poc
// Compile: g++ double-free.c -o double-free.exe 

int main() {
    HANDLE hHeap = GetProcessHeap();
    
    void* p1 = HeapAlloc(hHeap, 0, 64);
    printf("[*] P1 alloc at: %p\n", p1);

    void* p2 = HeapAlloc(hHeap, 0, 64);
    printf("[*] P2 alloc at: %p\n", p2);
	
	HeapFree(hHeap, 0, p1);
    printf("[*] P1 freed.\n");
	
	HeapFree(hHeap, 0, p2);
    printf("[*] P2 freed.\n");

    HeapFree(hHeap, 0, p1);
	printf("[+] Successful double free. System don't stop process.\n");

    return 0;
}

