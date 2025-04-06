#include "./GOffsets/GOffsets.h"
#include "./UEVersionScanner/UEVersionScanner.h"
#include "./EncryptionDetection/EncryptionDetection.h"

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#pragma comment(lib, "Version.lib")

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Close this window then drag and drop the Unreal Engine game onto this exe... OR\n";
        std::cout << "Usage: " << argv[0] << " <game file path>\n";
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::string gameFilePath = argv[1];
    size_t lastSlash = gameFilePath.find_last_of("\\/");
    std::string exeName = (lastSlash != std::string::npos) ? gameFilePath.substr(lastSlash + 1) : gameFilePath;
    std::vector<Byte> data = readBinaryFile(gameFilePath);
    if (data.empty()) {
        std::cout << "Error: Could not open file.\n\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Header output.
    std::cout << "----- GSpots : v1.5 -----\n\n";

    std::string ueVersion = GetUnrealEngineVersion(gameFilePath, exeName);
    if (ueVersion.rfind("1.", 0) == 0 || ueVersion.rfind("2.", 0) == 0) {
        ueVersion = "Undefined..";
    }
    std::cout << "\nUnreal Engine Version: " << ueVersion << "\n\n";

    // Check if the file is encrypted.
    bool fileEncrypted = IsFileEncrypted(data);

    // Scan file only if it's not encrypted.
    uint64_t fileGWorld = 0, fileGNames = 0, fileGObjects = 0;
    std::vector<Signature> signatures = getSignatures();
    if (!fileEncrypted) {
        for (const auto& sig : signatures) {
            size_t foundOffset = findPatternMask(data, sig.pattern, sig.mask);
            if (foundOffset != std::string::npos && foundOffset + 7 <= data.size()) {
                if (sig.name.find("GWorld") != std::string::npos && fileGWorld == 0)
                    foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GWorld");
                else if (sig.name.find("GNames") != std::string::npos && fileGNames == 0)
                    foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GNames");
                else if (sig.name.find("GObjects") != std::string::npos && fileGObjects == 0)
                    foundOffset = adjustFoundOffsetForGroup(data, foundOffset, "GObjects");

                int32_t disp = *reinterpret_cast<const int32_t*>(&data[foundOffset + 3]);
                size_t nextInstr = foundOffset + 7;
                size_t rawAddress = nextInstr + disp;
                uint32_t sectionDelta = getSectionDelta(data, foundOffset);
                uint64_t computedAddress = rawAddress + sectionDelta;

                if (sig.name.find("GWorld") != std::string::npos && fileGWorld == 0)
                    fileGWorld = computedAddress;
                else if (sig.name.find("GNames") != std::string::npos && fileGNames == 0)
                    fileGNames = computedAddress;
                else if (sig.name.find("GObjects") != std::string::npos && fileGObjects == 0)
                    fileGObjects = computedAddress;
            }
        }
    }
    // If the file is encrypted and the process is not running.
    else {
        DWORD dummyPID;
        if (!IsProcessRunning(exeName, dummyPID)) {
            std::cout << "It looks like this exe is encrypted but I might be able to find them in memory...";
        }
    }

    // Memory scanning: only if file scan failed and if process is running.
    DWORD processID = 0;
    bool processRunning = IsProcessRunning(exeName, processID);
    uint64_t memGWorld = 0, memGNames = 0, memGObjects = 0;
    if (processRunning) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess) {
            for (const auto& sig : signatures) {
                if (sig.name.find("GWorld") != std::string::npos && fileGWorld == 0 && memGWorld == 0)
                    memGWorld = findOffsetInProcessMemory(hProcess, sig.pattern, sig.mask, "GWorld");
                else if (sig.name.find("GNames") != std::string::npos && fileGNames == 0 && memGNames == 0)
                    memGNames = findOffsetInProcessMemory(hProcess, sig.pattern, sig.mask, "GNames");
                else if (sig.name.find("GObjects") != std::string::npos && fileGObjects == 0 && memGObjects == 0)
                    memGObjects = findOffsetInProcessMemory(hProcess, sig.pattern, sig.mask, "GObjects");
            }
            CloseHandle(hProcess);
        }
    }

    // Print offsets if found.
    if (fileGWorld != 0)
        std::cout << "GWorld Offset: 0x" << std::hex << std::uppercase << fileGWorld << "\n";
    else if (memGWorld != 0)
        std::cout << "GWorld Offset: 0x" << std::hex << std::uppercase << memGWorld << "\n";

    if (fileGNames != 0)
        std::cout << "GNames Offset: 0x" << std::hex << std::uppercase << fileGNames << "\n";
    else if (memGNames != 0)
        std::cout << "GNames Offset: 0x" << std::hex << std::uppercase << memGNames << "\n";

    if (fileGObjects != 0)
        std::cout << "GObjects Offset: 0x" << std::hex << std::uppercase << fileGObjects << "\n";
    else if (memGObjects != 0)
        std::cout << "GObjects Offset: 0x" << std::hex << std::uppercase << memGObjects << "\n";

    // If the file is encrypted and the process is running.
    if (fileEncrypted && processRunning && memGWorld && memGNames && memGObjects) {
        std::cout << "\nIt looks like the exe is encrypted..\nThere may be obfuscation happening that may render these offsets invalid.\n";
    }

    // Notify if any signature is missing.
    bool missing = false;
    if ((fileGWorld == 0 && memGWorld == 0) ||
        (fileGNames == 0 && memGNames == 0) ||
        (fileGObjects == 0 && memGObjects == 0))
    {
        missing = true;
    }
    if (!fileEncrypted) {
        if (missing) {
            if (fileGWorld == 0 && memGWorld == 0)
                std::cout << "GWorld signature not found...\n";
            if (fileGNames == 0 && memGNames == 0)
                std::cout << "GNames signature not found...\n";
            if (fileGObjects == 0 && memGObjects == 0)
                std::cout << "GObjects signature not found...\n";
            if (processRunning)
                std::cout << "\nSubmit a compatibility request on GSpots official GitHub!\n\n";
            else
                std::cout << "\nTry running the game in the background and try again!\n\n";
        }
    }
    else {
        if (!processRunning)
            std::cout << "\nTry running the game in the background and try again!\n\n";
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
