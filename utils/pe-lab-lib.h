#ifndef LIB
#define LIB

// *****************************************************
// * All struct defintions need for the parser to work *
// *****************************************************

#include <cstdint>
#include <fstream>

// Each entry points to a structure windows uses such as the import or the export table
struct ImageDataDirectoryEntry {
    uint32_t VA; // RVA of the table
    int32_t size; // Size of the section field
};


struct COFFHeader{
    uint16_t machine; // Machine type (eg. AMD64)
    uint16_t numOfSections; // Number of sections in file
    uint32_t timeDateStamp; // File creation time
    uint32_t pToSymbolTable; // Offset to COFF Header
    uint32_t numOfSymbols; // Number of entries in symbol table
    uint16_t sizeOfOptionalHeader; // Size of Optional Header, used later for parsing
    uint16_t characteristics; // Flag that indicate attributes of the file (eg. is the binary stripped, if its a DLL...)
};

// Part of the optional header defined for every COFF implementation
struct PE32StandardHeader {
    uint16_t magic; // Detemines if a file is 32 or 64bit
    uint8_t majorLinkerVersion; // self explanatory
    uint8_t minorLinkerVersion; // self explanatory
    uint32_t sizeOfCode; // Size of the code section
    uint32_t sizeOfInitializedData; // Size of initialized data section 
    uint32_t sizeOfUnitializedData; // Size of BSS section 
    uint32_t addressOfEntryPoint; // Address of entry point relative to image base
    uint32_t baseOfCode; // Relative to image base, points to beginning of the code section
    uint32_t baseOfData; // Relative to image base, points to beginning of the data section
};

// Part of optional header needed specifically for the windwos loader
struct PE32WindowsHeader {
    uint32_t imageBase; // Preferred address of the first byte in memory
    uint32_t sectionAlignment; // Alignment in bytes of sections when loaded into memory
    uint32_t fileAlignment; // The alignment factor in bytes used to align raw data in sections
    uint16_t majorOSVersion; // self explanatory
    uint16_t minorOSVersion; // self explanatory
    uint16_t majorImageVersion; // self explanatory
    uint16_t minorImageVersion;// self explanatory
    uint16_t majorSubsysVersion; // self explanatory
    uint16_t minotSubsysVersion; // self explanatory
    uint32_t win32VersionValue; // Reserver, must be 0
    uint32_t sizeOfImage; // Size of the image in bytes including all the headers
    uint32_t sizeOfHeaders; // Size of MZ, PE and section headers
    uint32_t checkSum; // self explanatory
    uint16_t subsystem; // Type of subsystem (eg. GUI, ROM, XBOX)
    uint16_t dllCharacteristics; // Some characteristics for DLLs (eg. NX compatiblity)
    uint32_t sizeOfStackReserve; // Size of stack to reserve
    uint32_t sizeOfStackCommit; // Size of stack to commit
    uint32_t sizeOfHeapReserve; // Size of local heap to reserve
    uint32_t sizeOfHeapCommit; // Size of local heap to commit
    uint32_t loaderFlags; // Reserved, must be 0
    uint32_t numOfRvaAndSizes; // Number of data directories in the remained of the optional header
};

struct PE32OptionalHeader {
    PE32StandardHeader standardHead; // All PE files have it
    PE32WindowsHeader winHead; // Required for the windows loader
};

// Same as for 32bit header
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


// Same as for 32bit header
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

// Same as 32bit Header
struct PE32PlusOptionalHeader {
    PE32PlusStandardHeader standardHead;
    PE32PlusWindowsHeader winHead;
};

// Each entry defines a section in the file
struct SectionTableEntry {
    uint8_t name[8]; // UTF-8 Encoded section name
    uint32_t virtualSize; // Size of the section when loaded into memory
    uint32_t virtualAddress; // Address of the first byte of the section relative to image base
    uint32_t sizeOfRawData; // Size of section on disk
    uint32_t pToRawData; // Pointer to the first byte of the section in the file
    uint32_t pToRelocations; // Pointer to the beginning of relocation entries
    uint32_t pToLinenumbers; // Pointer to the beginning of line number entries
    uint16_t numOfRelocations; // Number of reloaction entries
    uint16_t numOfLinenumbers; // Number of line number entries
    uint32_t characteristics; // Flags that describe the characteristics of section, such as the type of section and memory permissions
};

// Each entry in the IDT describes imports from one DLL
struct ImportDirectoryTableEntry {
    uint32_t ILT_RVA; // RVA of the import lookup table
    uint32_t timestamp; // Set to zero until the image is bound
    uint32_t forwarderChain; // Index of first forwarder reference
    uint32_t nameRVA; // RVA of the name of the DLL
    uint32_t IAT_RVA; // RVA of the import address table, same as the lookup table until the image is bound
};

struct ILTEntryPE32 {
    uint32_t bitField; // 0-30 (Name Table RVA) 0-15 (Ordinal number) 31/63 0 or 1 depending on import type
};

struct ILTEntryPE32Plus {
    uint64_t bitField;
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
    bool isOrdinalImport;

    HintTableEntry() {}
    HintTableEntry(uint16_t hint, std::string name, bool isOrdinalImport) {
        this->hint = hint;
        this->name = name;
        this->isOrdinalImport = isOrdinalImport;
    }
};

#endif
