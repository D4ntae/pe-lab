#include <iostream>
#include <fstream>
#include "../utils/pe-lab-lib.h"
#include <cstdint>
#include <map>
#include <vector>
#include <memory>


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
    ParsingInfo *parsingInfo = new ParsingInfo();
    COFFHeader *coffHeader = new COFFHeader();
    PE32OptionalHeader *optionalHeader32bit = new PE32OptionalHeader();
    PE32PlusOptionalHeader *optionalHeader64bit = new PE32PlusOptionalHeader();
    ImageDataDirectoryEntry *dataDirectoryTable = nullptr;
    SectionTableEntry *sectionTable = nullptr;

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
        infile->read((char *)coffHeader, sizeof(COFFHeader));
    }

    void parseOptionalHeader(uint32_t offset) {
        seek(offset);
        if (parsingInfo->is64bit) {
            infile->read((char *)optionalHeader64bit,sizeof(PE32PlusOptionalHeader));
        } else {
            infile->read((char *)optionalHeader32bit, sizeof(PE32OptionalHeader));
        }
    }

    void parseDataDirectories(uint32_t size, int offset) {
        if (size != 0) {
            dataDirectoryTable = new ImageDataDirectoryEntry[size];
            ImageDataDirectoryEntry idDir;
            for (int i = 0; i < size; i++) {
                seek(offset + i * sizeof(ImageDataDirectoryEntry));
                infile->read((char *)&idDir, sizeof(idDir));
                dataDirectoryTable[i] = idDir;
            }
        }
    }

    void parseSectionTable() {
        sectionTable = new SectionTableEntry[parsingInfo->numOfSections];
        SectionTableEntry e;
        for (int i = 0; i < parsingInfo->numOfSections; i++) {
            seek(parsingInfo->SectiontableOffset + i * sizeof(SectionTableEntry));
            infile->read((char *)&e, sizeof(e));
            sectionTable[i] = e;
        }
    }

    void parseImportTable() {
        // Used for offset calculations, pIDT points to the beginning of the
        // import section in the file, and the virtual address can be used
        // to calculate the offset to other parts of the table as it is the
        // virtual address of the beginning of the file
        uint32_t pIDT;
        uint32_t importVA;
        
        SectionTableEntry e;
        for (int i = 0; i < parsingInfo->numOfSections; i++) {
            e = sectionTable[i];
            if (namecmp(e.name, ".idata")) {
                pIDT = e.pToRawData;
                importVA = e.virtualAddress;
                break;
            }
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
