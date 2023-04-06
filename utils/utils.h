#ifndef UTILS
#define UTILS

#include <string>
#include <fstream>
#include <time.h>
#include <iostream>

char* getTime(uint32_t timestamp);
std::string getChars(uint16_t chars);
std::string getDLLChars(uint16_t chars); 
bool namecmp(uint8_t *name, const char *sectionName);
std::string readAscii(std::ifstream *infile, int offset);
std::string ltrim(const std::string &s);
std::string rtrim(const std::string &s);
std::string trim(const std::string &s);

#endif
