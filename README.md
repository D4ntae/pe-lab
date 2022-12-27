# pe-lab
THIS PROJECT IS IN BETA AND CURRENTLY IN DEVELOPMENT

A cross-platform PE file analyzer built in C++.

Currently extracts all data from DOS and NT Headers and the full import table with dll and function names if they exist.

Compile with:
g++ pe-lab.cpp pe-lab-lib.h -o pe-lab

Usage: ./pe-lab "path-to-pe-file"
