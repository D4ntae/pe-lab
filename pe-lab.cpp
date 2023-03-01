#include <iostream>
#include <fstream>
#include "pe-lab-lib.h"
#include <cstdint>
#include <map>
#include <vector>
#include <memory>

using namespace std;

class PEFile {    
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

    ifstream *infile;
    ParsingInfo *parsingInfo = new ParsingInfo();
    COFFHeader *coffHeader = new COFFHeader();
    PE32OptionalHeader *optionalHeader32bit = nullptr;
    PE32PlusOptionalHeader *optionalHeader64bit = nullptr;
    ImageDataDirectoryEntry *dataDirectoryTable = nullptr;
    SectionTableEntry *sectionTable = nullptr;

    // Seeks inside PE file currently pointed to by infile
    void seek(uint32_t offset) {
        infile->seekg(offset, ios::beg);
    }

    // Reads from PE file currently pointed to by infile
    void read(char *location) {
        infile->read(location, sizeof(*location));
    }

public:

    int initialParse() {
        // Parse location of PE signature
        seek(0x3c);
        read((char *)&(parsingInfo->peOffset));
        
        // Parse the signature
        char *pe = new char[4];
        seek(parsingInfo->peOffset);
        read(pe);
        if (!(pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' && pe[3] == '\0')) {
            cerr << "Invalid PE signature. Terminating\n";
            return 0;
        }
        delete [] pe;

        // COFFHeader is right after PE signature
        parsingInfo->COFFOffset = parsingInfo->peOffset + 4;
        // OptionalHeader is right after COFFHeader
        parsingInfo->OptionalHeaderOffset = parsingInfo->COFFOffset + sizeof(COFFHeader);

        // OptionalHeader start determines if the file is 32 or 64 bit
        uint16_t magic = 0;
        seek(parsingInfo->OptionalHeaderOffset);
        read((char *)&magic);

        if (magic == 0x20b) {
            parsingInfo->is64bit = true;
            parsingInfo->numOfRVAandSizes = parsingInfo->OptionalHeaderOffset + sizeof(PE32PlusOptionalHeader) - 4;
            parsingInfo->DataDirectoryOffset = parsingInfo->OptionalHeaderOffset + sizeof(PE32PlusOptionalHeader);

        } else if (magic == 0x10b) {
            parsingInfo->is64bit = false;
            parsingInfo->numOfRVAandSizes = parsingInfo->OptionalHeaderOffset + sizeof(PE32OptionalHeader) - 4;
            parsingInfo->DataDirectoryOffset = parsingInfo->OptionalHeaderOffset + sizeof(PE32OptionalHeader);
        } else {
            cerr << "Invalid OptionalHeader magic number. Terminating\n";
            return 0;
        }

        // Parse number of RVA and sizes needed for data directories
        seek(parsingInfo->numOfRVAandSizes);
        read((char *)&parsingInfo->numOfRVAandSizes);

        // SectionTable offset
        uint16_t optionalSize = 0;
        seek(parsingInfo->COFFOffset + 16); // location of sizeOfOptionalHeader
        read((char *)&optionalSize);
        parsingInfo->SectiontableOffset = parsingInfo->COFFOffset + sizeof(COFFHeader) + optionalSize;

        // Size of section table
        uint16_t num = 0;
        seek(parsingInfo->COFFOffset + 2);
        read((char *)&num);
        parsingInfo->numOfSections = num;


        return 1;
    }

    void parseCOFF() {
        seek(parsingInfo->COFFOffset);
        read((char *)coffHeader);
    }

    void parseOptionalHeader() {
        seek(parsingInfo->OptionalHeaderOffset);
        if (parsingInfo->is64bit) {
            read((char *)optionalHeader64bit);
        } else {
            read((char *)optionalHeader32bit);
        }
    }

    void parseDataDirectories() {
        if (parsingInfo->numOfRVAandSizes != 0) {
            dataDirectoryTable = new ImageDataDirectoryEntry[parsingInfo->numOfRVAandSizes];
            ImageDataDirectoryEntry idDir;
            for (int i = 0; i < parsingInfo->numOfRVAandSizes; i++) {
                seek(parsingInfo->DataDirectoryOffset + i * sizeof(ImageDataDirectoryEntry));
                read((char *)&idDir);
                dataDirectoryTable[i] = idDir;
            }
        }
    }

    void parseSectionTable() {
        sectionTable = new SectionTableEntry[parsingInfo->numOfSections];
        SectionTableEntry e;
        for (int i = 0; i < parsingInfo->numOfSections; i++) {
            seek(parsingInfo->SectiontableOffset + i * sizeof(SectionTableEntry));
            read((char *)&e);
            sectionTable[i] = e;
        }
    }

    void parseImportTable() {
        parseSectionTable();

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

    PEFile(ifstream *infile) {
        this->infile = infile;

        // Fills up initial offsets and info
        int valid = initialParse();

        if (!valid) {
            throw invalid_argument("Parsing Error"); // TODO
        }


    }
};

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        cerr << "No file name passed." << endl;
        std::cout << "Usage: pe-lab <filename>";
        return 1;
    }

    ifstream infile;
    infile.open(argv[1], ios::in | ios::binary);
    if (!infile) {
        cerr << "Error reading file" << endl;
        return 1;
    }

    uint32_t peOffset = 0;
    char *pe = new char[4];
    infile.seekg(0x3c, ios::beg);
    infile.read((char *)&peOffset, 4);
    infile.seekg(peOffset, ios::beg);
    infile.read(pe, 4);
    if (!(pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' && pe[3] == '\0')) {
        cerr << "Invalid PE signature. Terminating" << endl;
        return 1;
    }
    delete [] pe;

    // Read COFF Header
    /*

    */
    COFFHeader coffHeader;
    infile.seekg(peOffset + 4, ios::beg); // COFF Header starts right after PE signature
    infile.read((char *)&coffHeader, sizeof(COFFHeader));
    printCOFFHeaderInfo(&coffHeader);
    uint16_t magic = 0;
    uint32_t baseOfCode = 0;

    // Read Optional Header (Object file do not contain this header)
    if (coffHeader.sizeOfOptionalHeader) {
        infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg); // Optional header is right after COFF
        infile.read((char *)&magic, 2); // Magic is the start of the optional header, determines PE type
        if (magic == 0x20b) { // PE32+
            PE32PlusOptionalHeader optionalHeader;
            infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg);
            infile.read((char *)&optionalHeader, sizeof(PE32PlusOptionalHeader)); // Read all info from Optional Header
            printOptionalHeader(&optionalHeader);
            baseOfCode = optionalHeader.standardHead.baseOfCode;
            
            uint32_t dataDirOffset = peOffset + 4 + sizeof(COFFHeader) + sizeof(PE32PlusOptionalHeader);

            // Data part of optional headerd
            ImageDataDirectoryEntry *entries = new ImageDataDirectoryEntry[optionalHeader.winHead.numOfRvaAndSizes];
            ImageDataDirectoryEntry idDir;
            for (uint32_t i = 0; i < optionalHeader.winHead.numOfRvaAndSizes; i++) {
                infile.seekg(dataDirOffset + i * sizeof(ImageDataDirectoryEntry), ios::beg);
                infile.read((char *)&idDir, sizeof(ImageDataDirectoryEntry));
                entries[i] = idDir;
            }
            printDataDirectories(entries, optionalHeader.winHead.numOfRvaAndSizes);
            delete[] entries;
        } else { // PE32
            PE32OptionalHeader optionalHeader;
            infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg);
            infile.read((char *)&optionalHeader, sizeof(PE32OptionalHeader));
            printOptionalHeader(&optionalHeader);
            baseOfCode = optionalHeader.standardHead.baseOfCode;

            // Data part of optional header

            uint32_t dataDirOffset = peOffset + 4 + sizeof(COFFHeader) + sizeof(PE32PlusOptionalHeader);
            // Data part of optional headerd
            ImageDataDirectoryEntry *entries = new ImageDataDirectoryEntry[optionalHeader.winHead.numOfRvaAndSizes];
            ImageDataDirectoryEntry idDir;
            for (uint32_t i = 0; i < optionalHeader.winHead.numOfRvaAndSizes; i++) {
                infile.seekg(dataDirOffset + i * sizeof(ImageDataDirectoryEntry), ios::beg);
                infile.read((char *)&idDir, sizeof(ImageDataDirectoryEntry));
                entries[i] = idDir;
            }
            printDataDirectories(entries, optionalHeader.winHead.numOfRvaAndSizes);
            delete[] entries;
        }
    }

    // Section Table
    uint32_t sectionTableOffset = peOffset + 4 + sizeof(COFFHeader) + coffHeader.sizeOfOptionalHeader; // Located right after the optional header
    infile.seekg(sectionTableOffset, ios::beg);

    uint32_t pIDT;
    uint32_t importVA;
    SectionTableEntry *sectionEntries = new SectionTableEntry[coffHeader.numOfSections];
    for (int i = 0; i < coffHeader.numOfSections; i++) {
        infile.seekg(sectionTableOffset + sizeof(SectionTableEntry) * i, ios::beg);
        SectionTableEntry e;
        infile.read((char *)&e, sizeof(SectionTableEntry));
        sectionEntries[i] = e;
        if (namecmp(&e.name[0], ".idata")) {
            pIDT = e.pToRawData;
            importVA = e.virtualAddress;
        }
    }

    printSectionTableInfo(sectionEntries, coffHeader.numOfSections);
    delete[] sectionEntries;
    // Import Directory Table
    infile.seekg(pIDT, ios::beg);
    ImportDirectoryTableEntry e;
    int i = 0;
    vector<string> dllNames;
    map<DllNameFunctionNumber, vector<HintTableEntry>> *imports = new map<DllNameFunctionNumber, vector<HintTableEntry>>();
    while (true) {
        vector<HintTableEntry> entries;
        infile.seekg(pIDT + sizeof(ImportDirectoryTableEntry) * i, ios::beg);
        ImportDirectoryTableEntry e;
        infile.read((char *)&e, sizeof(ImportDirectoryTableEntry));
        if (e.IAT_RVA == 0) break;
        
        string dllName = readAscii(infile, (e.nameRVA - importVA) + pIDT);
        dllNames.push_back(dllName);


        if (magic == 0x20b) {        
            string name;
            int importCounter = 0;
            uint64_t ilt = 0;
            while (true) {
                infile.seekg((e.ILT_RVA - importVA) + pIDT + importCounter * 8, ios::beg); // seek to import lookup table
                infile.read((char *)&ilt, 8);
                if (ilt & 0x8000000000000000) {
                    cout << "No import info available" << endl;
                    break;;
                }
                if (ilt == 0) break;
                // Hint table reading
                uint16_t hint = 0;
                string name = readAscii(infile, (ilt - importVA) + pIDT + sizeof(uint16_t));
                bool pad = false;
                infile.seekg((ilt - importVA) + pIDT, ios::beg);
                infile.read((char *)&hint, 2);
                HintTableEntry *e = new HintTableEntry(hint, name, pad);
                entries.push_back(*e);
                importCounter++;
            }
            DllNameFunctionNumber member;
            member.name = dllName;
            member.numOfFunctions = importCounter;
            imports->insert({member, entries});
        } else {
            string name;
            int importCounter = 0;
            uint32_t ilt = 0;
            while (true) {
                infile.seekg((e.ILT_RVA - importVA) + pIDT + importCounter * 4, ios::beg); // seek to import lookup table
                infile.read((char *)&ilt, 8);
                if (ilt & 0x80000000) {
                    cout << "No import info available" << endl;
                    break;;
                }
                if (ilt == 0) break;
                // Hint table reading
                uint16_t hint = 0;
                string name = readAscii(infile, (ilt - importVA) + pIDT + sizeof(uint16_t));
                bool pad = false;
                infile.seekg((ilt - importVA) + pIDT, ios::beg);
                infile.read((char *)&hint, 2);
                HintTableEntry *e = new HintTableEntry(hint, name, pad);
                entries.push_back(*e);
                importCounter++;
            }
            DllNameFunctionNumber member;
            member.name = dllName;
            member.numOfFunctions = importCounter;
            imports->insert({member, entries});
        }
        i++;
    };

    printImports(imports);
    return 0;
}