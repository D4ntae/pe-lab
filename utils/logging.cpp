#include "pe-lab-lib.h"
#include "utils.h"
#include <vector>

std::map<uint16_t, const char *> machineType = {
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

std::map<uint16_t, const char *> subsystem = {
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

void printCOFFHeaderInfo(COFFHeader *header) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                   COFF Header Info                    ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << "  [*] Machine: " << machineType[header->machine] << std::endl;
    std::cout << "  [*] Sections #: " << header->numOfSections << std::endl;
    std::cout << "  [*] Time created: " << getTime(header->timeDateStamp);
    printf("  [*] Symbol table addr: 0x%x\n", header->pToSymbolTable);
    std::cout << "  [*] Symbols #: " << header->numOfSymbols << std::endl;
    std::cout << "  [*] Size of optional header: " << header->sizeOfOptionalHeader << std::endl;
    std::cout << "  [*] Characteristics: " << getChars(header->characteristics) << std::endl << std::endl;
}

void printOptionalHeader(PE32OptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    printf("  [*] Magic: 0x%x (PE32)\n", header->standardHead.magic);
    std::cout << "  [*] Major Linker Version: " << header->standardHead.majorLinkerVersion << std::endl;
    std::cout << "  [*] Minor Linker Version: " << header->standardHead.minorLinkerVersion << std::endl;
    std::cout << "  [*] Size of code: " << header->standardHead.sizeOfCode << std::endl;
    std::cout << "  [*] Size of init. data: " << header->standardHead.sizeOfInitializedData << std::endl;
    std::cout << "  [*] Size of uninit. data: " << header->standardHead.sizeOfUnitializedData << std::endl;
    printf("  [*] Addr of entry: 0x%x\n", header->standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header->standardHead.baseOfCode);
    printf("  [*] Base of data: 0x%x\n", header->standardHead.baseOfData); // Unqiue to PE32

    // Windows Header
    printf("  [*] Image Base: 0x%x (PE32)\n", header->winHead.imageBase);
    std::cout << "  [*] Section Alignment: " << header->winHead.sectionAlignment << std::endl;
    std::cout << "  [*] File Alignment: " << header->winHead.fileAlignment << std::endl;
    std::cout << "  [*] Major OS Version: " << header->winHead.majorOSVersion << std::endl;
    std::cout << "  [*] Minor OS Version: " << header->winHead.minorOSVersion << std::endl;
    std::cout << "  [*] Major Subsys. Version: " << header->winHead.majorSubsysVersion << std::endl;
    std::cout << "  [*] Minor Subsys. Version: " << header->winHead.minotSubsysVersion << std::endl;
    std::cout << "  [*] Win32 Version Value: " << header->winHead.win32VersionValue << std::endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Checksum: " << header->winHead.checkSum << std::endl;
    std::cout << "  [*] Subsystem: " << subsystem[header->winHead.subsystem] << std::endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Dll Characteristics: " << getDLLChars(header->winHead.dllCharacteristics) << std::endl;
    std::cout << "  [*] Size of Stack Reserve: " << header->winHead.sizeOfStackReserve << std::endl;
    std::cout << "  [*] Size of Stack Commit: " << header->winHead.sizeOfStackCommit << std::endl;
    std::cout << "  [*] Size of Heap Reserve: " << header->winHead.sizeOfHeapReserve << std::endl;
    std::cout << "  [*] Size of Heap Commit: " << header->winHead.sizeOfHeapCommit << std::endl;
    std::cout << "  [*] Loader Flags: " << header->winHead.loaderFlags << std::endl;
    std::cout << "  [*] Number of Rva and Sizes: " << header->winHead.numOfRvaAndSizes<< std::endl;
}

std::string getSectionEntryChars(SectionTableEntry *entry) {
    std::string ret = "";
    ret += entry->characteristics & 0x40000000 ? "r" : "-"; // check readable
    ret += entry->characteristics & 0x80000000 ? "w" : "-"; // check writable
    ret += entry->characteristics & 0x20000000 ? "x" : "-"; // check executable
    return ret;
}

void printSectionTableInfo(std::vector<SectionTableEntry> entries, uint32_t len) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                   Section Table Info                  ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    for (uint32_t i = 0; i < len; i++) {
        std::cout << "  [*] Name: " << std::setw(6) << entries[i].name << std::setfill(' ') << std::setw(5) << getSectionEntryChars(&entries[i]) << std::endl;
        std::cout << "  \t [+] Virtual size: " << entries[i].virtualSize << "\n";
        std::cout << "  \t [+] Virtual address: " << entries[i].virtualAddress << "\n";
        std::cout << "  \t [+] Size of raw data: " << entries[i].sizeOfRawData << "\n";
        std::cout << "  \t [+] Pointer to raw data: " << entries[i].pToRawData << "\n";
        std::cout << "  \t [+] Pointer to relocations: " << entries[i].pToRelocations << "\n";
        std::cout << "  \t [+] Pointer to line numbers: " << entries[i].pToLinenumbers << "\n";
        std::cout << "  \t [+] Number of relocations: " << entries[i].numOfRelocations << "\n";
        std::cout << "  \t [+] Number of line numbers: " << entries[i].numOfLinenumbers << "\n";
    }
}

void printOptionalHeader(PE32PlusOptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    printf("  [*] Magic: 0x%x (PE32+)\n", header->standardHead.magic);
    std::cout << "  [*] Major Linker Version: " << header->standardHead.majorLinkerVersion << std::endl;
    std::cout << "  [*] Minor Linker Version: " << header->standardHead.minorLinkerVersion << std::endl;
    std::cout << "  [*] Size of code: " << header->standardHead.sizeOfCode << std::endl;
    std::cout << "  [*] Size of init. data: " << header->standardHead.sizeOfInitializedData << std::endl;
    std::cout << "  [*] Size of uninit. data: " << header->standardHead.sizeOfUnitializedData << std::endl;
    printf("  [*] Addr of entry: 0x%x\n", header->standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header->standardHead.baseOfCode);

    // Windows Header
    printf("  [*] Image Base: 0x%lx (PE32+)\n", header->winHead.imageBase);
    std::cout << "  [*] Section Alignment: " << header->winHead.sectionAlignment << std::endl;
    std::cout << "  [*] File Alignment: " << header->winHead.fileAlignment << std::endl;
    std::cout << "  [*] Major OS Version: " << header->winHead.majorOSVersion << std::endl;
    std::cout << "  [*] Minor OS Version: " << header->winHead.minorOSVersion << std::endl;
    std::cout << "  [*] Major Subsys. Version: " << header->winHead.majorSubsysVersion << std::endl;
    std::cout << "  [*] Minor Subsys. Version: " << header->winHead.minotSubsysVersion << std::endl;
    std::cout << "  [*] Win32 Version Value: " << header->winHead.win32VersionValue << std::endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Checksum: " << header->winHead.checkSum << std::endl;
    std::cout << "  [*] Subsystem: " << subsystem[header->winHead.subsystem] << std::endl;
    std::cout << "  [*] Size of Headers: " << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Dll Characteristics: " << getDLLChars(header->winHead.dllCharacteristics) << std::endl;
    std::cout << "  [*] Size of Stack Reserve: " << header->winHead.sizeOfStackReserve << std::endl;
    std::cout << "  [*] Size of Stack Commit: " << header->winHead.sizeOfStackCommit << std::endl;
    std::cout << "  [*] Size of Heap Reserve: " << header->winHead.sizeOfHeapReserve << std::endl;
    std::cout << "  [*] Size of Heap Commit: " << header->winHead.sizeOfHeapCommit << std::endl;
    std::cout << "  [*] Loader Flags: " << header->winHead.loaderFlags << std::endl;
    std::cout << "  [*] Number of Rva and Sizes: " << header->winHead.numOfRvaAndSizes<< std::endl;
}

void printDataDirectories(std::vector<ImageDataDirectoryEntry> entries, uint32_t numOf) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########            Optional Header Data Directories           ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::string table[] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header"};
    for (uint32_t i = 0; i < numOf - 1; i++) {
        std::cout << "  [*] " << table[i] << ": {RVA: " << entries[i].VA << ", Size: " << entries[i].size << "}\n";
    }
}

void printImports(std::map<DllNameFunctionNumber, std::vector<HintTableEntry>> *imports) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                        Imports                        ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;

    for (std::map<DllNameFunctionNumber, std::vector<HintTableEntry>>::iterator it = imports->begin(); it != imports->end(); it++) {
        std::cout << "  [*] DLL Name: " << it->first.name << " " << "(" << it->first.numOfFunctions << " functions)" << std::endl;
        for (std::vector<HintTableEntry>::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++) {
            std::cout << "   - Name: " << it2->name;
            printf(" (Hint: %x)\n", it2->hint);
        }
    }
}
