#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <vector>
#include <string>
#include <cstdint>

using Byte = unsigned char;

struct Signature {
    std::string name;
    std::vector<Byte> pattern;
    std::string mask;
};

// Reads an entire binary file into a vector.
std::vector<Byte> readBinaryFile(const std::string& filename);

// Returns the hardcoded signatures.
std::vector<Signature> getSignatures();

// Searches for a pattern with wildcards in the data. 'x' = fixed byte, '?' = wildcard.
size_t findPatternMask(const std::vector<Byte>& data,
    const std::vector<Byte>& pattern,
    const std::string& mask);

// VirtualAddress - PointerToRawData.
uint32_t getSectionDelta(const std::vector<Byte>& data, size_t offset);

#endif 