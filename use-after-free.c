#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define ARGSIZE 512

// Author: Carlos Dominguez
// Based on: https://cwe.mitre.org/data/definitions/416.html
// Compile: gcc .\use-after-free.c -o .\use-after-free.exe [-g]

int main(int argc, char **argv)
{
    char *text;
    char *part1;
    char *part2;
    char *secret;
    int textSize;
    int mid;

    if (argc != 2) {
        fprintf(stderr, "Use: %s <argument>\n", argv[0]);
        return -1;
    }

    // Normal behavior: divide text at argument into 2 parts of same size
    text = (char *)malloc(ARGSIZE);
    part1 = (char *)malloc(ARGSIZE / 2);
    part2 = (char *)malloc(ARGSIZE / 2);
    printf("Text: 0x%p\n", text);
    printf("Part1: 0x%p\n", part1);
    printf("Part2: 0x%p\n", part2);

    strncpy(text, argv[1], ARGSIZE - 2);
    textSize = strlen(text);
    mid = textSize / 2;

    // Valid end of string in C language
    strncpy(part1, text, mid);
    part1[mid] = '\0';
    strncpy(part2, text + mid, ARGSIZE / 2 - 2);
    part2[ARGSIZE / 2 - 1] = '\0';

    // Pause before attack to analyse memory
    system("PAUSE");

    // Free of the involved variable
    free(text);

    // ...
    // Secret variable reuse memory freeing by text
    secret = (char *)malloc( ARGSIZE);
    printf("Secret: 0x%p\n", secret);
    // Possible secret reveal
    strncpy(secret, "\nHello, that message is private, you shouldn't be able to see it!\n", ARGSIZE - 2);
    // ...

    if(textSize < 2){
        printf("Text: %s\n", text);  // Use-after-free
        printf("Please, introduce some text with 2 or more letters as an argument\n");
        
        // Pause after attack to analyse memory
        system("PAUSE");
        return -1;
    }

    // Normal behavior
    printf("Text division into two parts of equal size:\n");
    printf("Part 1: %s\n", part1);
    printf("Part 2: %s\n", part2);

    free(part1);
    free(part2);
    free(secret);

    return 0;
}