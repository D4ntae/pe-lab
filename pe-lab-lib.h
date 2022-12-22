#include <iostream>
#include <time.h>
#include <iomanip>
#include <map>
#include <cstdint>
#include <fstream>
#include <algorithm>

using namespace std;

struct ImageDataDirectoryEntry {
    uint32_t VA;
    uint32_t size;
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

struct HintTableEntry {
    uint16_t hint;
    string name;
    bool pad;

    HintTableEntry() {}
    HintTableEntry(uint16_t hint, string name, bool pad) {
        this->hint = hint;
        this->name = name;
        this->pad = pad;
    }
};

map<uint16_t, const char *> machineType = {
    {0x0, "Machine Unknown"},
    {0x1d3, "Matsushita AM33"},
    {0x8664, "x64"},
    {0x1c0, "ARM little endian"},
    {0xaa64, "ARM64 little endian"},
    {0x1c4, "ARM Thumb-2 little endian"},
    {0xebc, "EFT byte code"},
    {0x14c, "Intel 386+"},
    {0x200, "Intel Itanium"},
    {0x6232, "LoongArch 32-bit"},
    {0x6264, "LoongArch 64-bit"},
    {0x9041, "Mitsubishi M32R little endian"},
    {0x266, "MIPS16"},
    {0x366, "MIPS with FPU"},
    {0x466, "MIPS16 with FPU"},
    {0x1f0, "Power PC little endian"},
    {0x1f1, "Power PC with floating point support"},
    {0x166, "MIPS little endian"},
    {0x5032, "RISC-V 32-bit"},
    {0x5064, "RISC-V 64-bit"},
    {0x5128, "RISC-V 128-bit"},
    {0x1a2, "Hitachi SH3"},
    {0x1a3, "Hitachi SH3 DSP"},
    {0x1a6, "Mitachi SH4"},
    {0x1a8, "Hitachi SH5"},
    {0x1c2, "Thumb"},
    {0x169, "MIPS little-endian WCE v2"}
};

map<uint16_t, const char *> subsystem = {
    {0, "Unknown"},
    {1, "Native"},
    {2, "GUI"},
    {3, "Console"},
    {5, "OS/2 Console"},
    {7, "Posix Console"},
    {8, "Native Win9x driver"},
    {9, "Windows CE"},
    {10, "EFI Application"},
    {11, "EFI driver with boot services"},
    {12,  "EFI driver with run-time services"},
    {13, "EFI ROM Image"},
    {14, "XBOX"},
    {16, "Windows Boot Application"}
};

char* getTime(uint32_t timestamp) {
    time_t a = timestamp;
    return ctime(&a);
}

string getChars(uint16_t chars) {
    string ret = "";
    if (chars & 0x0020) {
        ret += "PE32+, ";
    } else {
        ret += "PE32, ";
    }

    if (chars & 0x2000) {
        ret += "DLL, ";
    } else {
        ret += "EXE, ";
    }

    if (chars & 0x0200) {
        ret += "stripped";
    } else {
        ret += "not stripped";
    }

    return ret;
}

string getDLLChars(uint16_t chars) {
    string ret = "";
    if (chars & 0x0100) {
        ret += "NX compatible, ";
    }
    if (chars & 0x0400) {
        ret += "No SEH, ";
    }
    if (chars & 0x0800) {
        ret += "Do not bind";
    } else {
        ret += "Binding allowed";
    }

    return ret;
}

/*
struct COFFHeader{
    uint16_t machine;
    uint16_t numOfSections;
    uint32_t timeDateStamp;
    uint32_t pToSymbolTable;
    uint32_t numOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

*/

bool namecmp(uint8_t *name, const char *sectionName) {
    int i = 0;
    while (name[i] != 0 && i < 8) {
        if (name[i] != sectionName[i]) return false;
        i++;
    }
    return true;
}

string readAscii(ifstream &infile, int offset) {
    char c = 1;
    string ret;
    int i = 0;
    while (c != 0) {
        infile.seekg(offset + i, ios::beg);
        infile.read(&c, 1);
        ret += c;
        i++;
    }
    return ret;
}

const string WHITESPACE = " \n\r\t\f\v";

string ltrim(const string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == string::npos) ? "" : s.substr(start);
}

string rtrim(const string &s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == string::npos) ? "" : s.substr(0, end + 1);
}

string trim(const string &s) {
    return rtrim(ltrim(s));
}

void printCOFFHeaderInfo(COFFHeader *header) {
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########                   COFF Header Info                    ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << "  [*] Machine: " << machineType[header->machine] << endl;
    std::cout << "  [*] Sections #: " << header->numOfSections << endl;
    std::cout << "  [*] Time created: " << getTime(header->timeDateStamp);
    printf("  [*] Symbol table addr: 0x%x\n", header->pToSymbolTable);
    std::cout << "  [*] Symbols #: " << header->numOfSymbols << endl;
    std::cout << "  [*] Size of optional header: " << header->sizeOfOptionalHeader << endl;
    std::cout << "  [*] Characteristics: " << getChars(header->characteristics) << endl << endl;
}

void printOptionalHeader(PE32OptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    printf("  [*] Magic: 0x%x (PE32)\n", header->standardHead.magic);
    std::cout << "  [*] Major Linker Version: " << header->standardHead.majorLinkerVersion << endl;
    std::cout << "  [*] Minor Linker Version: " << header->standardHead.minorLinkerVersion << endl;
    std::cout << "  [*] Size of code: " << header->standardHead.sizeOfCode << endl;
    std::cout << "  [*] Size of init. data: " << header->standardHead.sizeOfInitializedData << endl;
    std::cout << "  [*] Size of uninit. data: " << header->standardHead.sizeOfUnitializedData << endl;
    printf("  [*] Addr of entry: 0x%x\n", header->standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header->standardHead.baseOfCode);
    printf("  [*] Base of data: 0x%x\n", header->standardHead.baseOfData); // Unqiue to PE32

    // Windows Header
    printf("  [*] Image Base: 0x%x (PE32)\n", header->winHead.imageBase);
    std::cout << "  [*] Section Alignment: " << header->winHead.sectionAlignment << endl;
    std::cout << "  [*] File Alignment: " << header->winHead.fileAlignment << endl;
    std::cout << "  [*] Major OS Version: " << header->winHead.majorOSVersion << endl;
    std::cout << "  [*] Minor OS Version: " << header->winHead.minorOSVersion << endl;
    std::cout << "  [*] Major Subsys. Version: " << header->winHead.majorSubsysVersion << endl;
    std::cout << "  [*] Minor Subsys. Version: " << header->winHead.minotSubsysVersion << endl;
    std::cout << "  [*] Win32 Version Value: " << header->winHead.win32VersionValue << endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << endl;
    std::cout << "  [*] Checksum: " << header->winHead.checkSum << endl;
    std::cout << "  [*] Subsystem: " << subsystem[header->winHead.subsystem] << endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << endl;
    std::cout << "  [*] Dll Characteristics: " << getDLLChars(header->winHead.dllCharacteristics) << endl;
    std::cout << "  [*] Size of Stack Reserve: " << header->winHead.sizeOfStackReserve << endl;
    std::cout << "  [*] Size of Stack Commit: " << header->winHead.sizeOfStackCommit << endl;
    std::cout << "  [*] Size of Heap Reserve: " << header->winHead.sizeOfHeapReserve << endl;
    std::cout << "  [*] Size of Heap Commit: " << header->winHead.sizeOfHeapCommit << endl;
    std::cout << "  [*] Loader Flags: " << header->winHead.loaderFlags << endl;
    std::cout << "  [*] Number of Rva and Sizes: " << header->winHead.numOfRvaAndSizes<< endl;
}

string getSectionEntryChars(SectionTableEntry *entry) {
    string ret = "";
    ret += entry->characteristics & 0x40000000 ? "r" : "-"; // check readable
    ret += entry->characteristics & 0x80000000 ? "w" : "-"; // check writable
    ret += entry->characteristics & 0x20000000 ? "x" : "-"; // check executable
    return ret;
}

void printSectionTableInfo(SectionTableEntry *entries, uint32_t len) {
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########                   Section Table Info                  ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    for (uint32_t i = 0; i < len; i++) {
        std::cout << "  [*] Name: " << setw(6) << entries[i].name << setfill(' ') << setw(5) << getSectionEntryChars(&entries[i]) << endl;
    }
}

void printOptionalHeader(PE32PlusOptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    printf("  [*] Magic: 0x%x (PE32+)\n", header->standardHead.magic);
    std::cout << "  [*] Major Linker Version: " << header->standardHead.majorLinkerVersion << endl;
    std::cout << "  [*] Minor Linker Version: " << header->standardHead.minorLinkerVersion << endl;
    std::cout << "  [*] Size of code: " << header->standardHead.sizeOfCode << endl;
    std::cout << "  [*] Size of init. data: " << header->standardHead.sizeOfInitializedData << endl;
    std::cout << "  [*] Size of uninit. data: " << header->standardHead.sizeOfUnitializedData << endl;
    printf("  [*] Addr of entry: 0x%x\n", header->standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header->standardHead.baseOfCode);

    // Windows Header
    printf("  [*] Image Base: 0x%lx (PE32+)\n", header->winHead.imageBase);
    std::cout << "  [*] Section Alignment: " << header->winHead.sectionAlignment << endl;
    std::cout << "  [*] File Alignment: " << header->winHead.fileAlignment << endl;
    std::cout << "  [*] Major OS Version: " << header->winHead.majorOSVersion << endl;
    std::cout << "  [*] Minor OS Version: " << header->winHead.minorOSVersion << endl;
    std::cout << "  [*] Major Subsys. Version: " << header->winHead.majorSubsysVersion << endl;
    std::cout << "  [*] Minor Subsys. Version: " << header->winHead.minotSubsysVersion << endl;
    std::cout << "  [*] Win32 Version Value: " << header->winHead.win32VersionValue << endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << endl;
    std::cout << "  [*] Checksum: " << header->winHead.checkSum << endl;
    std::cout << "  [*] Subsystem: " << subsystem[header->winHead.subsystem] << endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << endl;
    std::cout << "  [*] Dll Characteristics: " << getDLLChars(header->winHead.dllCharacteristics) << endl;
    std::cout << "  [*] Size of Stack Reserve: " << header->winHead.sizeOfStackReserve << endl;
    std::cout << "  [*] Size of Stack Commit: " << header->winHead.sizeOfStackCommit << endl;
    std::cout << "  [*] Size of Heap Reserve: " << header->winHead.sizeOfHeapReserve << endl;
    std::cout << "  [*] Size of Heap Commit: " << header->winHead.sizeOfHeapCommit << endl;
    std::cout << "  [*] Loader Flags: " << header->winHead.loaderFlags << endl;
    std::cout << "  [*] Number of Rva and Sizes: " << header->winHead.numOfRvaAndSizes<< endl;
}

void printDataDirectories(ImageDataDirectoryEntry *entries, uint32_t numOf) {
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########            Optional Header Data Directories           ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    string table[] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header"};
    for (uint32_t i = 0; i < numOf - 1; i++) {
        std::cout << "  [*] " << table[i] << ": {RVA: " << entries[i].VA << ", Size: " << entries[i].size << "}\n";
    }
}

void printImports(map<string, vector<HintTableEntry>> *imports) {
    std::cout << " +---------------------------------------------------------------------------+" << endl;
    std::cout << " |##########                        Imports                        ##########|" << endl;
    std::cout << " +---------------------------------------------------------------------------+" << endl;

    for (map<string, vector<HintTableEntry>>::iterator it = imports->begin(); it != imports->end(); it++) {
        std::cout << "  [*] DLL Name: " << it->first << endl;
        for (vector<HintTableEntry>::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++) {
            std::cout << "   - Name: " << it2->name;
            printf(" (Hint: %x)\n", it2->hint);
        }
    }
}