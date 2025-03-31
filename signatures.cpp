#include "signatures.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
};

struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

// Reads the binary file.
std::vector<Byte> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return {};
    }
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    std::vector<Byte> buffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    return buffer;
}

// Signatures
std::vector<Signature> getSignatures() {
    std::vector<Signature> sigs;
    // ----------------------------------------------
    // START GWORLDS
    // ----------------------------------------------

    sigs.push_back({ "GWorld (Variant 1)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x8B, 0x00, 0x00, 0x00,
         0xF6, 0x86, 0x3B, 0x01, 0x00, 0x00, 0x40},
        "xxx?????x???xxxxxxx"
        });

    sigs.push_back({ "GWorld (Variant 2)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x8B, 0x00, 0x00,
         0xF6, 0x86, 0x3B, 0x01, 0x00, 0x00, 0x40},
        "xxx?????x??xxxxxxx"
        });

    sigs.push_back({ "GWorld (Variant 3)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xF6, 0x86, 0x00, 0x01, 0x00, 0x00, 0x40},
        "xxx?????x?????xx?xxxx"
        });

    sigs.push_back({ "GWorld (Variant 4)",
        {0x00, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00,0x00},
        "?x???xx?xxx?????x???xx?????x?"
        });

    // ----------------------------------------------
    // END GWORLDS
    // ----------------------------------------------

    // ----------------------------------------------
    // START GNAMES
    // ----------------------------------------------

    sigs.push_back({ "GNames (Variant 1)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
         0xE8, 0x00, 0x00, 0xFE, 0xFF,
         0x4C, 0x8B, 0xC0,
         0xC6, 0x05, 0x00, 0x00, 0x00, 0x00,
         0x01},
        "xxx????x??xxxxxxx????x"
        });

    sigs.push_back({ "GNames (Variant 2)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00,
         0x03, 0xE8, 0x00, 0x00, 0xFF, 0xFF,
         0x4C, 0x00, 0xC0},
        "xxx???xx??xxx?x"
        });

    sigs.push_back({"GNames (Variant 3)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
         0xE8, 0x00, 0x00, 0xFF, 0xFF, 0x48, 0x8B, 0xD0,
         0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01},
        "xxx????x??xxxxxxx????x"
        });

    sigs.push_back({ "GNames (Variant 4)",
        {0x48, 0x8B, 0X05, 0X00, 0x00, 0x00, 0x02, 0x48,
         0x85, 0xC0, 0x75, 0x5F, 0xB9, 0x08, 0x08, 0x00},
        "xxx???xxxxxxxxx?"
        });

    // ----------------------------------------------
    // END GNAMES
    // ----------------------------------------------
     
    // ----------------------------------------------
	// START GOBJECTS
    // ----------------------------------------------

    sigs.push_back({"GObjects (Variant 1)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x03, 0x99, 0x0F,
         0xB7, 0xD2},
        "xxx???xxxxx"
        });

    sigs.push_back({"GObjects (Variant 2)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x41, 0x3B, 0xC0,
         0x7D, 0x17},
        "xxx????xxxxx"
        });

    sigs.push_back({"GObjects (Variant 3)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x04, 0x90, 0x0F, 0xB7,
         0xC6, 0x8B, 0xD6},
        "xxx???xxxxxxx"
        });

    sigs.push_back({ "GObjects (Variant 4)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x02, 0x99, 0x0F,
         0xB7, 0xD2},
        "xxx???xxxxx"
        });

    // ----------------------------------------------
    // END GOBJECTS
    // ----------------------------------------------

    return sigs;
}

// Searches for a pattern
size_t findPatternMask(const std::vector<Byte>& data,
    const std::vector<Byte>& pattern,
    const std::string& mask) {
    if (pattern.size() != mask.size() || pattern.empty() || data.empty())
        return std::string::npos;

    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found)
            return i;
    }
    return std::string::npos;
}

// Calculates adjustments to convert offsets within the PE
uint32_t getSectionDelta(const std::vector<Byte>& data, size_t offset) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER))
        return 0;
    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != 0x5A4D) // "MZ"
        return 0;
    size_t peHeaderOffset = dosHeader->e_lfanew;
    if (data.size() < peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
        return 0;
    const uint32_t* peSignature = reinterpret_cast<const uint32_t*>(data.data() + peHeaderOffset);
    if (*peSignature != 0x00004550) // "PE\0\0"
        return 0;
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(data.data() + peHeaderOffset + sizeof(uint32_t));
    size_t optHeaderOffset = peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    size_t sectionHeadersStart = optHeaderOffset + fileHeader->SizeOfOptionalHeader;

    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* section =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(data.data() + sectionHeadersStart + i * sizeof(IMAGE_SECTION_HEADER));
        uint32_t rawStart = section->PointerToRawData;
        uint32_t rawEnd = rawStart + section->SizeOfRawData;
        if (offset >= rawStart && offset < rawEnd) {
            return section->VirtualAddress - section->PointerToRawData;
        }
    }
    return 0;
}