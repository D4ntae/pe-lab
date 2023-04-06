#include <iostream>
#include <fstream>
#include <cstdint>
#include <map>
#include <vector>
#include <memory>

#include "../utils/pe-lab-lib.h"
#include "../utils/utils.h"
#include "../utils/logging.h"

class Parser {    
    struct ParsingInfo {
        uint32_t peOffset;
        uint32_t COFFOffset;
        uint32_t OptionalHeaderOffset;
        uint32_t DataDirectoryOffset;
        uint32_t SectiontableOffset;
        bool is64bit;
        uint32_t numOfRVAandSizes;
        uint16_t numOfSections;
    };

    std::ifstream *infile;
    std::unique_ptr<ParsingInfo> parsingInfo = std::make_unique<ParsingInfo>(); 
    std::unique_ptr<COFFHeader> coffHeader = std::make_unique<COFFHeader>();
    std::unique_ptr<PE32OptionalHeader> optionalHeader32bit = std::make_unique<PE32OptionalHeader>();
    std::unique_ptr<PE32PlusOptionalHeader> optionalHeader64bit = std::make_unique<PE32PlusOptionalHeader>();
    std::vector<ImageDataDirectoryEntry> dataDirectoryTable;
    std::vector<SectionTableEntry> sectionTable;
    std::vector<ImportDirectoryTableEntry> IDT;
    std::map<DllNameFunctionNumber, std::vector<HintTableEntry>> imports;

    // Seeks inside PE file currently pointed to by infile
    void seek(uint32_t offset) {
        infile->seekg(offset, std::ios::beg);
    }

    bool verifySignature() {
        char *pe = new char[4];
        seek(parsingInfo->peOffset);
        infile->read(pe, 4);
        if (!(pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' && pe[3] == '\0')) {
            return 0;
        }
        delete [] pe;
        return 1; 
    }

    void parseCOFF(uint32_t offset) {
        seek(offset);
        infile->read((char *)&(*coffHeader), sizeof(COFFHeader));
    }

    void parseOptionalHeader(uint32_t offset) {
        seek(offset);
        if (parsingInfo->is64bit) {
            infile->read((char *)&*optionalHeader64bit,sizeof(PE32PlusOptionalHeader));
        } else {
            infile->read((char *)&*optionalHeader32bit, sizeof(PE32OptionalHeader));
        }
    }

    void parseDataDirectories(uint32_t size, int offset) {
        if (size != 0) {
            ImageDataDirectoryEntry idDir;
            for (unsigned int i = 0; i < size; i++) {
                seek(offset + i * sizeof(ImageDataDirectoryEntry));
                infile->read((char *)&idDir, sizeof(idDir));
                dataDirectoryTable.push_back(idDir);
            }
        }
    }

    void parseSectionTable(int numOfSections, int offset) {
        SectionTableEntry e;
        for (int i = 0; i < numOfSections; i++) {
            seek(offset + i * sizeof(SectionTableEntry));
            infile->read((char *)&e, sizeof(e));
            sectionTable.push_back(e);
        }
    }

    SectionTableEntry locateImportTable(ImageDataDirectoryEntry importDir, std::vector<SectionTableEntry> sections) {
        SectionTableEntry importSection;
        for (SectionTableEntry section : sections) {
            if (importDir.VA >= section.virtualAddress && importDir.VA < section.virtualAddress + section.virtualSize) {
                 importSection = section;
            }
        }

        return importSection;
    }


    std::vector<HintTableEntry> getHintTableEntries(int ILT_offset, SectionTableEntry importSection, ImportDirectoryTableEntry idt_entry, int *functionNum) {
        int i = 1;
        std::vector<HintTableEntry> hintTable;
        if (parsingInfo->is64bit) {

        } else {
            ILTEntryPE32 entry;
            seek(ILT_offset);
            infile->read((char *)&entry, sizeof(ILTEntryPE32));
            while (entry.bitField != 0) {
                if (entry.bitField & 0x80000000) {
                    std::cout << "Ordinal: " << (entry.bitField & 0x80000000);
                } else {
                    uint16_t hint;
                    seek(importSection.pToRawData + (entry.bitField - importSection.virtualAddress));
                    infile->read((char *)&hint, sizeof(hint));
                    std::string importName = readAscii(infile, importSection.pToRawData + (entry.bitField + 2 - importSection.virtualAddress)); 
                    HintTableEntry h_entry(hint, importName, true);
                    hintTable.push_back(h_entry);
                }
                seek(ILT_offset + i * sizeof(ILTEntryPE32));
                infile->read((char*)&entry, sizeof(entry));
                i++;
            }
        }
        *functionNum = i - 1;
        return hintTable;
    }

    void parseImportTable(ImageDataDirectoryEntry importDir, std::vector<SectionTableEntry> sections) {
        SectionTableEntry importSection = locateImportTable(importDir, sections); 
        ImportDirectoryTableEntry e;
        int import_offset = importSection.pToRawData + (importDir.VA - importSection.virtualAddress);
        
        seek(import_offset);
        infile->read((char *)&e, sizeof(e));
        int i = 1;
        while (e.nameRVA != 0) {
            IDT.push_back(e);
            seek(import_offset + i * sizeof(ImportDirectoryTableEntry));
            infile->read((char *)&e, sizeof(e));
            i++;
        }

        for (ImportDirectoryTableEntry idt_entry : IDT) {
            int functionNum = 0;
            int ILT_offset = importSection.pToRawData + (idt_entry.ILT_RVA - importSection.virtualAddress); 
            std::string dllName = readAscii(infile, importSection.pToRawData + (idt_entry.nameRVA - importSection.virtualAddress));
            std::vector<HintTableEntry> hintTable = getHintTableEntries(ILT_offset, importSection, idt_entry, &functionNum);
            DllNameFunctionNumber temp(functionNum, dllName);
            imports.insert({temp, hintTable});
        }

    }

public:

    int initialParse() {
        // Parse location of PE signature
        seek(0x3c);
        infile->read((char *)&(parsingInfo->peOffset), sizeof(parsingInfo->peOffset));
        
        // Parse and verify the signature
        if (!verifySignature()) {
            std::cerr << "Invalid PE signature. Terminating\n";
            return 0;
        }

        // COFFHeader is right after PE signature
        parsingInfo->COFFOffset = parsingInfo->peOffset + 4;
        parseCOFF(parsingInfo->COFFOffset);
        printCOFFHeaderInfo(&*this->coffHeader);

        // OptionalHeader is right after COFFHeader
        parsingInfo->OptionalHeaderOffset = parsingInfo->COFFOffset + sizeof(COFFHeader);

        // OptionalHeader start determines if the file is 32 or 64 bit
        uint16_t magic = 0;
        seek(parsingInfo->OptionalHeaderOffset);
        infile->read((char *)&magic, sizeof(magic));
        if (magic == 0x20b) {
            parsingInfo->is64bit = true;
            parsingInfo->numOfRVAandSizes = parsingInfo->OptionalHeaderOffset + sizeof(PE32PlusOptionalHeader) - 4;
            parsingInfo->DataDirectoryOffset = parsingInfo->OptionalHeaderOffset + sizeof(PE32PlusOptionalHeader);

        } else if (magic == 0x10b) {
            parsingInfo->is64bit = false;
            parsingInfo->numOfRVAandSizes = parsingInfo->OptionalHeaderOffset + sizeof(PE32OptionalHeader) - 4;
            parsingInfo->DataDirectoryOffset = parsingInfo->OptionalHeaderOffset + sizeof(PE32OptionalHeader);
        } else {
            std::cerr << "Invalid OptionalHeader magic number. Terminating\n"; 
            return 0;
        }
        parseOptionalHeader(parsingInfo->OptionalHeaderOffset);

        // Parse number of RVA and sizes needed for data directories
        seek(parsingInfo->numOfRVAandSizes);
        infile->read((char *)&(parsingInfo->numOfRVAandSizes), sizeof(parsingInfo->numOfRVAandSizes));
        parseDataDirectories(parsingInfo->numOfRVAandSizes, parsingInfo->DataDirectoryOffset);

        printDataDirectories(dataDirectoryTable, parsingInfo->numOfRVAandSizes);

        
        // Parse Section Headers
        parseSectionTable(coffHeader->numOfSections, parsingInfo->COFFOffset + sizeof(COFFHeader) + coffHeader->sizeOfOptionalHeader);
        printSectionTableInfo(sectionTable, coffHeader->numOfSections);

        parseImportTable(dataDirectoryTable[1], sectionTable);
        printImports(imports);
        return 1;
    }

    Parser(std::ifstream *infile) {
        this->infile = infile;

        // Fills up initial offsets and info
        int valid = initialParse();

        if (!valid) {
            throw std::invalid_argument("Parsing Error"); // TODO
        }


    }
};

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::cerr << "No file name passed." << std::endl;
        std::cout << "Usage: pe-lab <filename>";
        return 1;
    }
    
    std::ifstream infile;
    infile.open(argv[1], std::ios::in | std::ios::binary);
    if (!infile) {
        std::cerr << "Error reading file" << std::endl;
        return 1;
    }
    
    Parser *f = new Parser(&infile);
    return 0;
}
