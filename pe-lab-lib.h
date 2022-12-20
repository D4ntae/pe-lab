#include <iostream>
#include <time.h>
#include <iomanip>
#include <map>

using namespace std;

struct ImageDataDirectoryEntry {
    int VA;
    int size;
};

struct COFFHeader{
    short machine;
    short numOfSections;
    int timeDateStamp;
    int pToSymbolTable;
    int numOfSymbols;
    short sizeOfOptionalHeader;
    short characteristics;
};

struct PE32StandardHeader {
    short magic;
    char majorLinkerVersion;
    char minorLinkerVersion;
    int sizeOfCode;
    int sizeOfInitializedData;
    int sizeOfUnitializedData;
    int addressOfEntryPoint;
    int baseOfCode;
    int baseOfData;
};

struct PE32WindowsHeader {
    int imageBase;
    int sectionAlignment;
    int fileAlignment;
    short majorOSVersion;
    short minorOSVersion;
    short majorImageVersion;
    short minorImageVersion;
    short majorSubsysVersion;
    short minotSubsysVersion;
    int win32VersionValue;
    int sizeOfImage;
    int sizeOfHeaders;
    int checkSum;
    short subsystem;
    short dllCharacteristics;
    int sizeOfStackReserve;
    int sizeOfStackCommit;
    int sizeOfHeapReserve;
    int sizeOfHeapCommit;
    int loaderFlags;
    int numOfRvaAndSizes;
};

struct PE32OptionalHeader {
    PE32StandardHeader standardHead;
    PE32WindowsHeader winHead;
};

struct PE32PlusStandardHeader {
    short magic;
    char majorLinkerVersion;
    char minorLinkerVersion;
    int sizeOfCode;
    int sizeOfInitializedData;
    int sizeOfUnitializedData;
    int addressOfEntryPoint;
    int baseOfCode;
};

struct PE32PlusWindowsHeader {
    long imageBase;
    int sectionAlignment;
    int fileAlignment;
    short majorOSVersion;
    short minorOSVersion;
    short majorImageVersion;
    short minorImageVersion;
    short majorSubsysVersion;
    short minotSubsysVersion;
    int win32VersionValue;
    int sizeOfImage;
    int sizeOfHeaders;
    int checkSum;
    short subsystem;
    short dllCharacteristics;
    long sizeOfStackReserve;
    long sizeOfStackCommit;
    long sizeOfHeapReserve;
    long sizeOfHeapCommit;
    int loaderFlags;
    int numOfRvaAndSizes;
};

struct PE32PlusOptionalHeader {
    PE32PlusStandardHeader standardHead;
    PE32PlusWindowsHeader winHead;
};

struct SectionTableEntry {
    char name[8];
    int virtualSize;
    int virtualAddress;
    int sizeOfRawData;
    int pToRawData;
    int pToRelocations;
    int pToLinenumbers;
    short numOfRelocations;
    short numOfLinenumbers;
    int characteristics;
};

map<unsigned short, const char *> machineType = {
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

map<unsigned short, const char *> subsystem = {
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

char * getTime(int timestamp) {
    time_t a = timestamp;
    return ctime(&a);
}

string getChars(short chars) {
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

string getDLLChars(short chars) {
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
    short machine;
    short numOfSections;
    int timeDateStamp;
    int pToSymbolTable;
    int numOfSymbols;
    short sizeOfOptionalHeader;
    short characteristics;
};

*/

void printCOFFHeaderInfo(COFFHeader header) {
    cout << " +---------------------------------------------------------------------------+" << endl;
    cout << " |##########                   COFF Header Info                    ##########|" << endl;
    cout << " +---------------------------------------------------------------------------+" << endl;
    cout << "  [*] Machine: " << machineType[header.machine] << endl;
    cout << "  [*] Sections #: " << header.numOfSections << endl;
    cout << "  [*] Time created: " << getTime(header.timeDateStamp);
    printf("  [*] Symbol table addr: 0x%x\n", header.pToSymbolTable);
    cout << "  [*] Symbols #: " << header.numOfSymbols << endl;
    cout << "  [*] Size of optional header: " << header.sizeOfOptionalHeader << endl;
    cout << "  [*] Characteristics: " << getChars(header.characteristics) << endl << endl;
}

void printOptionalHeader(PE32OptionalHeader header) {
    // Standard Header
    cout << " +---------------------------------------------------------------------------+" << endl;
    cout << " |##########                  Optional Header Info                 ##########|" << endl;
    cout << " +---------------------------------------------------------------------------+" << endl;
    printf("  [*] Magic: 0x%x (PE32)\n", header.standardHead.magic);
    cout << "  [*] Major Linker Version: " << header.standardHead.majorLinkerVersion << endl;
    cout << "  [*] Minor Linker Version: " << header.standardHead.minorLinkerVersion << endl;
    cout << "  [*] Size of code: " << header.standardHead.sizeOfCode << endl;
    cout << "  [*] Size of init. data: " << header.standardHead.sizeOfInitializedData << endl;
    cout << "  [*] Size of uninit. data: " << header.standardHead.sizeOfUnitializedData << endl;
    printf("  [*] Addr of entry: 0x%x\n", header.standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header.standardHead.baseOfCode);
    printf("  [*] Base of data: 0x%x\n", header.standardHead.baseOfData); // Unqiue to PE32

    // Windows Header
    printf("  [*] Image Base: 0x%x (PE32)\n", header.winHead.imageBase);
    cout << "  [*] Section Alignment: " << header.winHead.sectionAlignment << endl;
    cout << "  [*] File Alignment: " << header.winHead.fileAlignment << endl;
    cout << "  [*] Major OS Version: " << header.winHead.majorOSVersion << endl;
    cout << "  [*] Minor OS Version: " << header.winHead.minorOSVersion << endl;
    cout << "  [*] Major Subsys. Version: " << header.winHead.majorSubsysVersion << endl;
    cout << "  [*] Minor Subsys. Version: " << header.winHead.minotSubsysVersion << endl;
    cout << "  [*] Win32 Version Value: " << header.winHead.win32VersionValue << endl;
    cout << "  [*] Size of Headers: " << header.winHead.sizeOfHeaders << endl;
    cout << "  [*] Checksum: " << header.winHead.checkSum << endl;
    cout << "  [*] Subsystem: " << subsystem[header.winHead.subsystem] << endl;
    cout << "  [*] Size of Headers: " << header.winHead.sizeOfHeaders << endl;
    cout << "  [*] Dll Characteristics: " << getDLLChars(header.winHead.dllCharacteristics) << endl;
    cout << "  [*] Size of Stack Reserve: " << header.winHead.sizeOfStackReserve << endl;
    cout << "  [*] Size of Stack Commit: " << header.winHead.sizeOfStackCommit << endl;
    cout << "  [*] Size of Heap Reserve: " << header.winHead.sizeOfHeapReserve << endl;
    cout << "  [*] Size of Heap Commit: " << header.winHead.sizeOfHeapCommit << endl;
    cout << "  [*] Loader Flags: " << header.winHead.loaderFlags << endl;
    cout << "  [*] Number of Rva and Sizes: " << header.winHead.numOfRvaAndSizes<< endl;
}

void printOptionalHeader(PE32PlusOptionalHeader header) {
    // Standard Header
    cout << " +---------------------------------------------------------------------------+" << endl;
    cout << " |##########                  Optional Header Info                 ##########|" << endl;
    cout << " +---------------------------------------------------------------------------+" << endl;
    printf("  [*] Magic: 0x%x (PE32+)\n", header.standardHead.magic);
    cout << "  [*] Major Linker Version: " << header.standardHead.majorLinkerVersion << endl;
    cout << "  [*] Minor Linker Version: " << header.standardHead.minorLinkerVersion << endl;
    cout << "  [*] Size of code: " << header.standardHead.sizeOfCode << endl;
    cout << "  [*] Size of init. data: " << header.standardHead.sizeOfInitializedData << endl;
    cout << "  [*] Size of uninit. data: " << header.standardHead.sizeOfUnitializedData << endl;
    printf("  [*] Addr of entry: 0x%x\n", header.standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header.standardHead.baseOfCode);

    // Windows Header
    printf("  [*] Image Base: 0x%lx (PE32+)\n", header.winHead.imageBase);
    cout << "  [*] Section Alignment: " << header.winHead.sectionAlignment << endl;
    cout << "  [*] File Alignment: " << header.winHead.fileAlignment << endl;
    cout << "  [*] Major OS Version: " << header.winHead.majorOSVersion << endl;
    cout << "  [*] Minor OS Version: " << header.winHead.minorOSVersion << endl;
    cout << "  [*] Major Subsys. Version: " << header.winHead.majorSubsysVersion << endl;
    cout << "  [*] Minor Subsys. Version: " << header.winHead.minotSubsysVersion << endl;
    cout << "  [*] Win32 Version Value: " << header.winHead.win32VersionValue << endl;
    cout << "  [*] Size of Headers: " << header.winHead.sizeOfHeaders << endl;
    cout << "  [*] Checksum: " << header.winHead.checkSum << endl;
    cout << "  [*] Subsystem: " << subsystem[header.winHead.subsystem] << endl;
    cout << "  [*] Size of Headers: " << header.winHead.sizeOfHeaders << endl;
    cout << "  [*] Dll Characteristics: " << getDLLChars(header.winHead.dllCharacteristics) << endl;
    cout << "  [*] Size of Stack Reserve: " << header.winHead.sizeOfStackReserve << endl;
    cout << "  [*] Size of Stack Commit: " << header.winHead.sizeOfStackCommit << endl;
    cout << "  [*] Size of Heap Reserve: " << header.winHead.sizeOfHeapReserve << endl;
    cout << "  [*] Size of Heap Commit: " << header.winHead.sizeOfHeapCommit << endl;
    cout << "  [*] Loader Flags: " << header.winHead.loaderFlags << endl;
    cout << "  [*] Number of Rva and Sizes: " << header.winHead.numOfRvaAndSizes<< endl;
}

void printDataDirectories(ImageDataDirectoryEntry entries[], int numOf) {
    cout << " +---------------------------------------------------------------------------+" << endl;
    cout << " |##########            Optional Header Data Directories           ##########|" << endl;
    cout << " +---------------------------------------------------------------------------+" << endl;
    string table[] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header"};
    for (int i = 0; i < numOf - 1; i++) {
        cout << "  [*] " << table[i] << ": {RVA: " << entries[i].VA << ", Size: " << entries[i].size << "}\n";
    }
}