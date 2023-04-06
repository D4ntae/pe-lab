#ifndef LOGGING
#define LOGGING

#include "pe-lab-lib.h"
#include <iostream>
#include <vector>

void printCOFFHeaderInfo(COFFHeader *header);
void printOptionalHeader(PE32OptionalHeader *header);
std::string getSectionEntryChars(SectionTableEntry *entry);
void printSectionTableInfo(std::vector<SectionTableEntry> entries, uint32_t len);
void printOptionalHeader(PE32PlusOptionalHeader *header); 
void printDataDirectories(std::vector<ImageDataDirectoryEntry> entries, uint32_t numOf);
void printImports(std::map<DllNameFunctionNumber, std::vector<HintTableEntry>> imports); 

#endif
