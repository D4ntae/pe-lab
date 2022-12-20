#include <iostream>
#include <fstream>
#include "pe-lab-lib.h"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        cerr << "No file name passed." << endl;
        cout << "Usage: pe-lab <filename>";
        return 1;
    }

    ifstream infile;
    infile.open(argv[1], ios::in | ios::binary);
    if (!infile) {
        cerr << "Error reading file" << endl;
        return 1;
    }

    int peOffset = 0;
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
    COFFHeader coffHeader;
    infile.seekg(peOffset + 4, ios::beg);
    infile.read((char *)&coffHeader, sizeof(COFFHeader));
    printCOFFHeaderInfo(coffHeader);

    // Read Optional Header
    if (coffHeader.sizeOfOptionalHeader) {
        infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg); // Optional header is right after COFF
        short magic = 0;
        infile.read((char *)&magic, 2);
        if (magic == 0x20b) { // PE32+
            PE32PlusOptionalHeader optionalHeader;
            infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg);
            infile.read((char *)&optionalHeader, sizeof(PE32PlusOptionalHeader));
            printOptionalHeader(optionalHeader);
            
            int dataDirOffset = peOffset + 4 + sizeof(COFFHeader) + sizeof(PE32PlusOptionalHeader);
            // Data part of optional headerd
            ImageDataDirectoryEntry entries[optionalHeader.winHead.numOfRvaAndSizes];
            ImageDataDirectoryEntry idDir;
            for (int i = 0; i < optionalHeader.winHead.numOfRvaAndSizes; i++) {
                infile.seekg(dataDirOffset + i * sizeof(ImageDataDirectoryEntry), ios::beg);
                infile.read((char *)&idDir, sizeof(ImageDataDirectoryEntry));
                entries[i] = idDir;
            }
            printDataDirectories(entries, optionalHeader.winHead.numOfRvaAndSizes);

            // Section Table
            int sectionTableOffset = peOffset + 4 + sizeof(COFFHeader) + coffHeader.sizeOfOptionalHeader;
            infile.seekg(sectionTableOffset, ios::beg);
            SectionTableEntry e;
            infile.read((char *)&e, sizeof(SectionTableEntry));
            cout << e.name;

        } else { // PE32
            PE32OptionalHeader optionalHeader;
            infile.seekg(peOffset + 4 + sizeof(COFFHeader), ios::beg);
            infile.read((char *)&optionalHeader, sizeof(PE32OptionalHeader));
            printOptionalHeader(optionalHeader);

            // Data part of optional header

            int dataDirOffset = peOffset + 4 + sizeof(COFFHeader) + sizeof(PE32PlusOptionalHeader);
            // Data part of optional headerd
            ImageDataDirectoryEntry entries[optionalHeader.winHead.numOfRvaAndSizes];
            ImageDataDirectoryEntry idDir;
            for (int i = 0; i < optionalHeader.winHead.numOfRvaAndSizes; i++) {
                infile.seekg(dataDirOffset + i * sizeof(ImageDataDirectoryEntry), ios::beg);
                infile.read((char *)&idDir, sizeof(ImageDataDirectoryEntry));
                entries[i] = idDir;
            }
            printDataDirectories(entries, optionalHeader.winHead.numOfRvaAndSizes);

            // Section Table
            int sectionTableOffset = peOffset + 4 + sizeof(COFFHeader) + coffHeader.sizeOfOptionalHeader;
            infile.seekg(sectionTableOffset, ios::beg);
            SectionTableEntry e;
            infile.read((char *)&e, sizeof(SectionTableEntry));
            e.name[8] = '\0';
            cout << e.name;
        }
    }

    return 0;
}