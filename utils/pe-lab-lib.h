#ifndef LIB
#define LIB

#include <iostream>
#include <time.h>
#include <iomanip>
#include <map>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include <vector>


struct ImageDataDirectoryEntry {
    uint32_t VA;
    int32_t size;
};

struct COFFHeader{
    uint16_t machine;
    uint16_t numOfSections;
    uint32_t timeDateStamp;
    uint32_t pToSymbolTable;
    uint32_t numOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct PE32StandardHeader {
    uint16_t magic;
    uint8_t majorLinkerVersion;
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUnitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint32_t baseOfData;
};

struct PE32WindowsHeader {
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOSVersion;
    uint16_t minorOSVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsysVersion;
    uint16_t minotSubsysVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numOfRvaAndSizes;
};

struct PE32OptionalHeader {
    PE32StandardHeader standardHead;
    PE32WindowsHeader winHead;
};

struct PE32PlusStandardHeader {
    uint16_t magic;
    uint8_t majorLinkerVersion;
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUnitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
};

struct PE32PlusWindowsHeader {
    uint64_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOSVersion;
    uint16_t minorOSVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsysVersion;
    uint16_t minotSubsysVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numOfRvaAndSizes;
};

struct PE32PlusOptionalHeader {
    PE32PlusStandardHeader standardHead;
    PE32PlusWindowsHeader winHead;
};

struct SectionTableEntry {
    uint8_t name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pToRawData;
    uint32_t pToRelocations;
    uint32_t pToLinenumbers;
    uint16_t numOfRelocations;
    uint16_t numOfLinenumbers;
    uint32_t characteristics;
};

struct ImportDirectoryTableEntry {
    uint32_t ILT_RVA;
    uint32_t timestamp;
    uint32_t forwarderChain;
    uint32_t nameRVA;
    uint32_t IAT_RVA;
};

struct ILTEntryPE32 {
    uint32_t bitField; // 0-30 (Name Table RVA) 0-15 (Ordinal number) 31/63 0 or 1 depending on import type
};

struct ILTEntryPE32Plus {

};

struct DllNameFunctionNumber {
    std::string name;
    int numOfFunctions;

    bool operator <(const DllNameFunctionNumber &other)const {
        return name < other.name;
    }
    DllNameFunctionNumber(int numOfFunctions, std::string name) {
        this->name = name;
        this->numOfFunctions = numOfFunctions;
    }
    DllNameFunctionNumber() {}
};

struct HintTableEntry {
    uint16_t hint;
    std::string name;
    bool pad;

    HintTableEntry() {}
    HintTableEntry(uint16_t hint, std::string name, bool pad) {
        this->hint = hint;
        this->name = name;
        this->pad = pad;
    }
};

#endif
