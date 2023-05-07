// *************************************************
// * Various utility functions related mostly to   *
// * making the output look better and for getting *
// * strings out of memory                         *
// *************************************************

#include <fstream>

char* getTime(uint32_t timestamp) {
    time_t a = timestamp;
    return ctime(&a);
}

std::string getChars(uint16_t chars) {
    std::string ret = "";
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

std::string getDLLChars(uint16_t chars) {
    std::string ret = "";
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

bool namecmp(uint8_t *name, const char *sectionName) {
    int i = 0;
    while (name[i] != 0 && i < 8) {
        if (name[i] != sectionName[i]) return false;
        i++;
    }
    return true;
}

std::string readAscii(std::ifstream *infile, int offset) {
    char c = 1;
    std::string ret;
    int i = 0;
    while (c != 0) {
        infile->seekg(offset + i, std::ios::beg);
        infile->read(&c, 1);
        ret += c;
        i++;
    }
    return ret;
}

std::string ltrim(const std::string &s) {
    const std::string WHITESPACE = " \n\r\t";
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

std::string rtrim(const std::string &s) {
    const std::string WHITESPACE = " \n\r\t";
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::string trim(const std::string &s) {
    return rtrim(ltrim(s));
}
