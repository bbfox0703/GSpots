#include "signatures.h"
#include <iostream>
#include <string>
#include <vector>

// Fixed prefix to allow signatures to start anywhere within/before the Gs range.
size_t adjustFoundOffsetForGroup(const std::vector<Byte>& data, size_t foundOffset, const std::string& group) {
    std::vector<std::vector<Byte>> prefixes;
    if (group == "GWorld") {
        prefixes.push_back({ 0x48, 0x89, 0x05 });
    }
    else if (group == "GNames") {
		prefixes.push_back({ 0x48, 0x8D, 0x0D }); // > 4.27 
        prefixes.push_back({ 0x48, 0x8B, 0x05 }); // < 4.27 idfk
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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Close this window then drag and drop the Unreal Engine game onto this exe... OR\n" << std::endl;
        std::cout << "Usage: " << argv[0] << " <game file path>\n" << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::string gameFilePath = argv[1];

    std::vector<Byte> data = readBinaryFile(gameFilePath);
    if (data.empty()) {
        std::cout << "Error..\n\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::vector<Signature> signatures = getSignatures();
    
    // Put XOR encrypted GObjects here..

    // Put chunk padding for nullptr here..

    bool foundGWorld = false;
    bool foundGNames = false;
    bool foundGObjects = false;

    // Iterate over each signature and output the first matching signature for each group.
    for (const auto& sig : signatures) {
        size_t foundOffset = findPatternMask(data, sig.pattern, sig.mask);
        if (foundOffset != std::string::npos && foundOffset + 7 <= data.size()) {
            // If the signature is for a group that requires adjustment, update the offset.
            if (sig.name.find("GWorld") != std::string::npos)
                foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GWorld");
            else if (sig.name.find("GNames") != std::string::npos)
                foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GNames");
            else if (sig.name.find("GObjects") != std::string::npos)
                foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GObjects");

            // Reads the 4-byte displacement following the base opcode.
            int32_t disp = *reinterpret_cast<const int32_t*>(&data[foundOffset + 3]);
            size_t nextInstr = foundOffset + 7; 
            size_t rawAddress = nextInstr + disp;
            uint32_t sectionDelta = getSectionDelta(data, foundOffset);
            uint64_t computedAddress = rawAddress + sectionDelta;

            if (sig.name.find("GWorld") != std::string::npos && !foundGWorld) {
                std::cout << "GWorld Offset: 0x" << std::hex << std::uppercase << computedAddress << "\n" << std::endl;
                foundGWorld = true;
            }
            else if (sig.name.find("GNames") != std::string::npos && !foundGNames) {
                std::cout << "GNames Offset: 0x" << std::hex << std::uppercase << computedAddress << "\n" << std::endl;
                foundGNames = true;
            }
            else if (sig.name.find("GObjects") != std::string::npos && !foundGObjects) {
                std::cout << "GObjects Offset: 0x" << std::hex << std::uppercase << computedAddress << "\n" << std::endl;
                foundGObjects = true;
            }
        }
    }

    if (!foundGWorld)
        std::cout << "GWorld signature not found or insufficient data.\n" << std::endl;
    if (!foundGNames)
        std::cout << "GNames signature not found or insufficient data.\n" << std::endl;
    if (!foundGObjects)
        std::cout << "GObjects signature not found or insufficient data.\n" << std::endl;

    std::cout << "\n\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
