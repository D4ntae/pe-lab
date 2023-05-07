// ****************************************************************
// * Functions related to printing output to the screen and       *
// * matching codes to strings such as machine name               *
// ****************************************************************

#include "pe-lab-lib.h"
#include "utils.h"
#include "string.h"
#include <map>
#include <cstdint>
#include <iomanip>
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

void printWithPad(const char* startString, uint64_t toPrint, int maxSize) {
    std::cout << startString << std::setfill('.') << std::setw(maxSize - strlen(startString) + 1) << " " << std::setfill('0') << "0x" << std::setw(8) << toPrint << "\n";  
}

void printWithPad(const char* startString, const char* toPrint, int maxSize) {
    std::cout << startString << std::setfill('.') << std::setw(maxSize - strlen(startString) + 1) << " " << toPrint << "\n";  
};

void printCOFFHeaderInfo(COFFHeader *header) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                   COFF Header Info                    ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    printWithPad("  [*] Machine ", machineType[header->machine], 30);
    printWithPad("  [*] Sections nums ", header->numOfSections, 30);
    printWithPad("  [*] Time created ", getTime(header->timeDateStamp), 30);
    printWithPad("  [*] Symbol table addr ", header->pToSymbolTable, 30);
    printWithPad("  [*] Symbols nums ", header->numOfSymbols, 30);
    printWithPad("  [*] Size of optional header ", header->sizeOfOptionalHeader, 30);
    printWithPad("  [*] Characteristics ", getChars(header->characteristics).c_str(), 30);
}


void printOptionalHeader(PE32OptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    printWithPad("  [*] Magic ", header->standardHead.magic, 29);
    printWithPad("  [*] Major Linker Version ", header->standardHead.majorLinkerVersion, 29);
    printWithPad("  [*] Minor Linker Version ", header->standardHead.minorLinkerVersion, 29);
    printWithPad("  [*] Size of code ", header->standardHead.sizeOfCode, 29);
    printWithPad("  [*] Size of init. data ", header->standardHead.sizeOfInitializedData, 29);
    printWithPad("  [*] Size of uninit. data ", header->standardHead.sizeOfUnitializedData, 29);
    printWithPad("  [*] Addr of entry ", header->standardHead.addressOfEntryPoint, 29);
    printWithPad("  [*] Base of code ", header->standardHead.baseOfCode, 29);
    printWithPad("  [*] Base of data ", header->standardHead.baseOfData, 29);

    // Windows Header
    printWithPad("  [*] Image Base: ", header->winHead.imageBase, 29);
    printWithPad("  [*] Section Alignment ", header->winHead.sectionAlignment, 29);
    printWithPad("  [*] File Alignment ", header->winHead.fileAlignment, 29);
    printWithPad("  [*] Major OS Version ", header->winHead.majorOSVersion, 29);
    printWithPad("  [*] Minor OS Version ", header->winHead.minorOSVersion, 29);
    printWithPad("  [*] Major Subsys. Version ", header->winHead.majorSubsysVersion, 29);
    printWithPad("  [*] Minor Subsys. Version ", header->winHead.minotSubsysVersion, 29);
    printWithPad("  [*] Win32 Version Value ", header->winHead.win32VersionValue, 29);
    printWithPad("  [*] Size of Headers ", header->winHead.sizeOfHeaders, 29);
    printWithPad("  [*] Checksum ", header->winHead.checkSum, 29);
    printWithPad("  [*] Subsys ", header->winHead.subsystem, 29);
    printWithPad("  [*] Size of Image ", header->winHead.sizeOfImage, 29);
    printWithPad("  [*] Dll Characteristics ", header->winHead.dllCharacteristics, 29);
    printWithPad("  [*] Size of Stack Reserve ", header->winHead.sizeOfStackReserve, 29);
    printWithPad("  [*] Size of Stack Commit ", header->winHead.sizeOfStackCommit, 29);
    printWithPad("  [*] Size of Heap Reserve ", header->winHead.sizeOfHeapReserve, 29);
    printWithPad("  [*] Size of Heap Commit ", header->winHead.sizeOfHeapCommit, 29);
    printWithPad("  [*] Loader Flags ", header->winHead.loaderFlags, 29);
    printWithPad("  [*] Numer of Rva and Sizes ", header->winHead.numOfRvaAndSizes, 28);
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
    std::cout << "\n";
    for (uint32_t i = 0; i < len; i++) {
        std::cout << "  [*] Name: " << std::setw(6) << std::setfill(' ') << entries[i].name << std::setfill(' ') << std::setw(5) << getSectionEntryChars(&entries[i]) << std::endl;
        std::cout << "  ------------------------\n";
        printWithPad("    [+] Virtual size ", entries[i].virtualSize, 32);
        printWithPad("    [+] Virtual address ", entries[i].virtualAddress, 32);
        printWithPad("    [+] Size of raw data ", entries[i].sizeOfRawData, 32);
        printWithPad("    [+] Poitner to raw data ", entries[i].pToRawData, 32);
        printWithPad("    [+] Poitner to relocations ", entries[i].pToRelocations, 32);
        printWithPad("    [+] Poitner to line numbers ", entries[i].pToLinenumbers, 32);
        printWithPad("    [+] Number of relocations ", entries[i].numOfRelocations, 32);
        printWithPad("    [+] Number of line numbers ", entries[i].numOfLinenumbers, 32);
        std::cout << "\n";
    }
}

void printOptionalHeader(PE32PlusOptionalHeader *header) {
    // Standard Header
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                  Optional Header Info                 ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    printf("  [*] Magic: 0x%x (PE32+)\n", header->standardHead.magic);
    std::cout << "  [*] Major Linker Version: " << std::setw(8) << header->standardHead.majorLinkerVersion << std::endl;
    std::cout << "  [*] Minor Linker Version: " << "0x" << std::setw(8) << header->standardHead.minorLinkerVersion << std::endl;
    std::cout << "  [*] Size of code: " << "0x" << std::setw(8) << header->standardHead.sizeOfCode << std::endl;
    std::cout << "  [*] Size of init. data: " << "0x" << std::setw(8) << header->standardHead.sizeOfInitializedData << std::endl;
    std::cout << "  [*] Size of uninit. data: " << "0x" << std::setw(8) << header->standardHead.sizeOfUnitializedData << std::endl;
    printf("  [*] Addr of entry: 0x%x\n", header->standardHead.addressOfEntryPoint);
    printf("  [*] Base of code: 0x%x\n", header->standardHead.baseOfCode);

    // Windows Header
    printf("  [*] Image Base: 0x%lx (PE32+)\n", header->winHead.imageBase);
    std::cout << "  [*] Section Alignment: " << "0x" << std::setw(8) << header->winHead.sectionAlignment << std::endl;
    std::cout << "  [*] File Alignment: " << "0x" << std::setw(8) << header->winHead.fileAlignment << std::endl;
    std::cout << "  [*] Major OS Version: " << "0x" << std::setw(8) << header->winHead.majorOSVersion << std::endl;
    std::cout << "  [*] Minor OS Version: " << "0x" << std::setw(8) << header->winHead.minorOSVersion << std::endl;
    std::cout << "  [*] Major Subsys. Version: " << "0x" << std::setw(8) << header->winHead.majorSubsysVersion << std::endl;
    std::cout << "  [*] Minor Subsys. Version: " << "0x" << std::setw(8) << header->winHead.minotSubsysVersion << std::endl;
    std::cout << "  [*] Win32 Version Value: " << "0x" << std::setw(8) << header->winHead.win32VersionValue << std::endl;
    std::cout << "  [*] Size of Headers: " << "0x" << std::setw(8) << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Checksum: " << "0x" << std::setw(8) << header->winHead.checkSum << std::endl;
    std::cout << "  [*] Subsystem: " << "0x" << std::setw(8) << subsystem[header->winHead.subsystem] << std::endl;
    std::cout << "  [*] Size of Headers: " << "0x" << std::setw(8) << header->winHead.sizeOfHeaders << std::endl;
    std::cout << "  [*] Dll Characteristics: " << getDLLChars(header->winHead.dllCharacteristics) << std::endl;
    std::cout << "  [*] Size of Stack Reserve: " << "0x" << std::setw(8) << header->winHead.sizeOfStackReserve << std::endl;
    std::cout << "  [*] Size of Stack Commit: " << "0x" << std::setw(8) << header->winHead.sizeOfStackCommit << std::endl;
    std::cout << "  [*] Size of Heap Reserve: " << "0x" << std::setw(8) << header->winHead.sizeOfHeapReserve << std::endl;
    std::cout << "  [*] Size of Heap Commit: " << "0x" << std::setw(8) << header->winHead.sizeOfHeapCommit << std::endl;
    std::cout << "  [*] Loader Flags: " << "0x" << std::setw(8) << header->winHead.loaderFlags << std::endl;
    std::cout << "  [*] Number of Rva and Sizes: " << "0x" << std::setw(8) << header->winHead.numOfRvaAndSizes<< std::endl;
}

void printDataDirectories(std::vector<ImageDataDirectoryEntry> entries, uint32_t numOf) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########            Optional Header Data Directories           ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::string table[] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header"};
    for (uint32_t i = 0; i < numOf - 1; i++) {
        std::cout << "  [*] " << table[i] << "\n";
        printWithPad("    RVA", entries[i].VA, 8);
        printWithPad("    Size", entries[i].size, 8);
        std::cout << "\n";
    }
}

void printImports(std::map<DllNameFunctionNumber, std::vector<HintTableEntry>> imports) {
    std::cout << " +---------------------------------------------------------------------------+" << std::endl;
    std::cout << " |##########                        Imports                        ##########|" << std::endl;
    std::cout << " +---------------------------------------------------------------------------+\n" << std::endl;
    for (std::map<DllNameFunctionNumber, std::vector<HintTableEntry>>::iterator it = imports.begin(); it != imports.end(); it++) {
        std::cout << "  [*] " <<  it->first.name << "\t" << std::dec << it->first.numOfFunctions << " function(s)" << "\n";
        if (!it->second[0].isOrdinalImport) {
            std::cout << "  +-----------------------------------------+\n";
            std::cout << "  |\tHINT    NAME                        |\n";
            std::cout << "  +-----------------------------------------+\n";
        } else {
            std::cout << "  +-----------------------------------------+\n";
            std::cout << "  |\tORDINAL                             |\n";
            std::cout << "  +-----------------------------------------+\n";

        }
        for (std::vector<HintTableEntry>::iterator it2 = it->second.begin(); it2 != it->second.end(); it2++) {
            if (it2->isOrdinalImport) {
                std::cout << "  \t" << it2->hint << std::endl;
            } else {
                std::cout << "\t" << "0x" << std::hex << std::setfill('0') << std::setw(4) << it2->hint;
                std::cout << "\t" << it2->name << "\n";
            }
        }
        std::cout << "\n";
    }
}
