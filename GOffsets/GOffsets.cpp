#include "GOffsets.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <windows.h>
#include <Psapi.h>
#include <iomanip>

// Maximum allowed size for files and process images to prevent excessive memory use.
constexpr size_t MAX_FILE_SIZE = 500ULL * 1024ULL * 1024ULL;     // 500 MB
constexpr size_t MAX_IMAGE_SIZE = 2000ULL * 1024ULL * 1024ULL;   // 2000 MB

// Reads the binary file.
std::vector<Byte> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return {};
    }
    file.seekg(0, std::ios::end);
    std::streampos fileSizePos = file.tellg();
    if (fileSizePos == std::streampos(-1)) {
        std::cerr << "Error: Failed to determine size of " << filename << std::endl;
        return {};
    }
    size_t fileSize = static_cast<size_t>(fileSizePos);
    if (fileSize > MAX_FILE_SIZE) {
        std::cerr << "Error: File " << filename << " is too large (" << fileSize
                  << " bytes; limit is " << MAX_FILE_SIZE << ")." << std::endl;
        return {};
    }
    std::vector<Byte> buffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    if (!file || static_cast<size_t>(file.gcount()) != fileSize) {
        std::cerr << "Error: Failed to read file " << filename << std::endl;
        return {};
    }
    return buffer;
}

std::vector<Byte> parseHexPattern(const std::string& hexPattern) {
    std::vector<Byte> pattern;
    std::istringstream iss(hexPattern);
    std::string byteStr;
    
    while (iss >> byteStr) {
        if (byteStr == "??") {
            pattern.push_back(0x00);
        } else {
            pattern.push_back(static_cast<Byte>(std::stoul(byteStr, nullptr, 16)));
        }
    }
    return pattern;
}

std::vector<Signature> loadSignaturesFromJSON(const std::string& filename) {
    std::vector<Signature> sigs;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open signatures file: " << filename << std::endl;
        std::cerr << "Using built-in fallback signatures." << std::endl;
        return getBuiltinSignatures();
    }

    std::string line;
    std::string content;
    while (std::getline(file, line)) {
        content += line;
    }
    file.close();

    size_t pos = 0;
    std::string categories[] = {"gworld", "gnames", "gobjects"};
    
    for (const auto& category : categories) {
        std::string searchKey = "\"" + category + "\":";
        size_t categoryPos = content.find(searchKey);
        if (categoryPos == std::string::npos) continue;
        
        size_t arrayStart = content.find('[', categoryPos);
        if (arrayStart == std::string::npos) continue;
        
        size_t arrayEnd = content.find(']', arrayStart);
        if (arrayEnd == std::string::npos) continue;
        
        std::string arrayContent = content.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
        
        size_t objStart = 0;
        while ((objStart = arrayContent.find('{', objStart)) != std::string::npos) {
            size_t objEnd = arrayContent.find('}', objStart);
            if (objEnd == std::string::npos) break;
            
            std::string objContent = arrayContent.substr(objStart + 1, objEnd - objStart - 1);
            
            std::string name, pattern, mask;
            
            size_t namePos = objContent.find("\"name\":");
            if (namePos != std::string::npos) {
                size_t nameStart = objContent.find('\"', namePos + 7) + 1;
                size_t nameEnd = objContent.find('\"', nameStart);
                if (nameEnd != std::string::npos) {
                    name = objContent.substr(nameStart, nameEnd - nameStart);
                }
            }
            
            size_t patternPos = objContent.find("\"pattern\":");
            if (patternPos != std::string::npos) {
                size_t patternStart = objContent.find('\"', patternPos + 10) + 1;
                size_t patternEnd = objContent.find('\"', patternStart);
                if (patternEnd != std::string::npos) {
                    pattern = objContent.substr(patternStart, patternEnd - patternStart);
                }
            }
            
            size_t maskPos = objContent.find("\"mask\":");
            if (maskPos != std::string::npos) {
                size_t maskStart = objContent.find('\"', maskPos + 7) + 1;
                size_t maskEnd = objContent.find('\"', maskStart);
                if (maskEnd != std::string::npos) {
                    mask = objContent.substr(maskStart, maskEnd - maskStart);
                }
            }
            
            if (!name.empty() && !pattern.empty() && !mask.empty()) {
                sigs.push_back({name, parseHexPattern(pattern), mask});
            }
            
            objStart = objEnd + 1;
        }
    }
    
    if (sigs.empty()) {
        std::cerr << "Warning: No valid signatures loaded from JSON. Using built-in fallback." << std::endl;
        return getBuiltinSignatures();
    }
    
    return sigs;
}

std::vector<Signature> getBuiltinSignatures() {
    std::vector<Signature> sigs;
    // Fallback built-in signatures
    sigs.push_back({ "GWorld (Variant 1)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x8B, 0x00, 0x00, 0x00,
         0xF6, 0x86, 0x3B, 0x01, 0x00, 0x00,
         0x40},
        "xxx?????x???xxxxxxx"
        });
    sigs.push_back({ "GNames (Variant 1)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0xE8, 0x00, 0x00, 0xFE, 0xFF,
         0x4C, 0x8B, 0xC0, 0xC6, 0x05, 0x00,
         0x00, 0x00, 0x00, 0x01},
        "xxx????x??xxxxxxx????x"
        });
    sigs.push_back({ "GObjects (Variant 1)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0x99, 0x0F, 0xB7, 0xD2},
        "xxx????xxxx"
        });
    return sigs;
}

// Load signatures from JSON file, fallback to built-in
std::vector<Signature> getSignatures() {
    return loadSignaturesFromJSON("config/signatures.json");
}

// Searches for a pattern.
size_t findPatternMask(const std::vector<Byte>& data,
    const std::vector<Byte>& pattern,
    const std::string& mask) {
    if (pattern.size() != mask.size() || pattern.empty() || data.empty())
        return std::string::npos;
    if (data.size() < pattern.size())
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

// Calculates adjustments to convert offsets within the PE.
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

// Memory scanning fallback to find offsets in the process memory.
uint64_t findOffsetInProcessMemory(HANDLE hProcess, const std::vector<Byte>& pattern, const std::string& mask, const std::string& group) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        return 0;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo)))
        return 0;
    if (modInfo.SizeOfImage > MAX_IMAGE_SIZE) {
        std::cerr << "Error: Module image size " << modInfo.SizeOfImage
                  << " bytes exceeds limit of " << MAX_IMAGE_SIZE << std::endl;
        return 0;
    }
    std::vector<Byte> buffer(static_cast<size_t>(modInfo.SizeOfImage));
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, buffer.data(),
                           static_cast<SIZE_T>(modInfo.SizeOfImage), &bytesRead))
        return 0;

    buffer.resize(bytesRead);

    size_t foundOffset = findPatternMask(buffer, pattern, mask);
    if (foundOffset == std::string::npos || foundOffset + 7 > bytesRead)
        return 0;
    foundOffset = adjustFoundOffsetForGroup(buffer, foundOffset, group);
    int32_t disp = *reinterpret_cast<const int32_t*>(&buffer[foundOffset + 3]);
    size_t nextInstr = foundOffset + 7;
    size_t rawAddress = nextInstr + disp;
    uint64_t rva = rawAddress;
    return rva;
}

// Adjusts the found offset based on a group-specific prefix.
// For example, if scanning for "GWorld", we may search nearby for a known instruction prefix.
size_t adjustFoundOffsetForGroup(const std::vector<Byte>& data, size_t foundOffset, const std::string& group) {
    std::vector<std::vector<Byte>> prefixes;
    if (group == "GWorld") {
        prefixes.push_back({ 0x48, 0x89, 0x05 });
    }
    else if (group == "GNames") {
        prefixes.push_back({ 0x48, 0x8D, 0x0D }); // <= 4.27
        prefixes.push_back({ 0x48, 0x8B, 0x05 }); // > 4.27
    }
    else if (group == "GObjects") {
        prefixes.push_back({ 0x4C, 0x8B, 0x0D });
    }
    else {
        return foundOffset;
    }
    size_t searchLimit = 30;
    size_t limit = (foundOffset + searchLimit < data.size()) ? foundOffset + searchLimit : data.size();
    for (size_t i = foundOffset; i <= limit; i++) {
        for (const auto& prefix : prefixes) {
            if (i + prefix.size() > data.size())
                continue;
            bool match = true;
            for (size_t j = 0; j < prefix.size(); j++) {
                if (data[i + j] != prefix[j]) {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }
    }
    return foundOffset;
}
