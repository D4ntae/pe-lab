#include <iostream>
#include <fstream>
#include "pe-lab-lib.h"
#include <cstdint>
#include <map>
#include <vector>
#include <memory>

using namespace std;

class PEFile {    
    struct Offsets {
        uint32_t peOffset;
        uint32_t COFFOffset;
        uint32_t OptionalHeaderOffset;
        bool is64bit;
    };

    ifstream *infile;
    Offsets *offsets = new Offsets();
    COFFHeader *coffHeader = new COFFHeader();
    PE32OptionalHeader *optionalHeader32bit = nullptr;
    PE32PlusOptionalHeader *optionalHeader64bit = nullptr;

    // Seeks inside PE file currently pointed to by infile
    void seek(uint32_t offset) {
        infile->seekg(offset, ios::beg);
    }

public:

    int initialParse() {
        // Parse location of PE signature
        seek(0x3c);
        infile->read((char *)&(offsets->peOffset), 4);
        
        // Parse the signature
        char *pe = new char[4];
        seek(offsets->peOffset);
        infile->read(pe, 4);
        if (!(pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' && pe[3] == '\0')) {
            cerr << "Invalid PE signature. Terminating\n";
            return 0;
        }
        delete [] pe;

        // COFFHeader is right after PE signature
        offsets->COFFOffset = offsets->peOffset + 4;
        // OptionalHeader is right after COFFHeader
        offsets->OptionalHeaderOffset = offsets->COFFOffset + sizeof(COFFHeader);

        // OptionalHeader start determines if the file is 32 or 64 bit
        uint16_t magic = 0;
        seek(offsets->OptionalHeaderOffset);
        infile->read((char *)&magic, 2);

        if (magic == 0x20b) {
            offsets->is64bit = true;
        } else if (magic == 0x10b) {
            offsets->is64bit = false;
        } else {
            cerr << "Invalid OptionalHeader magic number. Terminating\n";
            return 0;
        }

        return 1;
    }

    void parseCOFF() {
        seek(offsets->COFFOffset);
        infile->read((char *)coffHeader, sizeof(COFFHeader));
    }

    void parseOptionalHeader() {
        seek(offsets->OptionalHeaderOffset);
        if (offsets->is64bit) {
            infile->read((char *)optionalHeader64bit, sizeof(PE32PlusOptionalHeader));
        } else {
            infile->read((char *)optionalHeader32bit, sizeof(PE32OptionalHeader));
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