#include "goffsets.h"
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

// Unreal Engine version detection taken from my other repository https://github.com/Do0ks/UEVersionScanner.

// Reads an entire file into a string.
std::string ReadEntireFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Does the file exist?
bool FileExists(const std::string& filePath) {
    DWORD attrib = GetFileAttributesA(filePath.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Get version info from the resources.
std::string GetVersionFromResource(const std::string& filePath) {
    char modulePath[MAX_PATH] = { 0 };
    strcpy_s(modulePath, filePath.c_str());
    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeA(modulePath, &dummy);
    if (size == 0)
        return "";
    std::vector<char> data(size);
    if (!GetFileVersionInfoA(modulePath, 0, size, data.data()))
        return "";
    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT len = 0;
    if (VerQueryValueA(data.data(), "\\", (LPVOID*)&fileInfo, &len) && fileInfo) {
        int major = HIWORD(fileInfo->dwFileVersionMS);
        int minor = LOWORD(fileInfo->dwFileVersionMS);
        int build = HIWORD(fileInfo->dwFileVersionLS);
        int revision = LOWORD(fileInfo->dwFileVersionLS);
        char versionStr[128];
        sprintf_s(versionStr, "%d.%d.%d.%d", major, minor, build, revision);
        return versionStr;
    }
    return "";
}

// Try to get version info from candidate files near the executable.
std::string GetVersionFromFiles(const std::string& filePath) {
    char modulePath[MAX_PATH] = { 0 };
    strcpy_s(modulePath, filePath.c_str());
    std::string exePath(modulePath);
    size_t lastSlash = exePath.find_last_of("\\/");
    std::string exeDir;
    if (lastSlash != std::string::npos)
        exeDir = exePath.substr(0, lastSlash);
    std::vector<std::string> candidates;
    candidates.push_back(exeDir + "\\Engine\\Build\\Build.version");
    candidates.push_back(exeDir + "\\UE4Version.txt");
    candidates.push_back(exeDir + "\\UE5Version.txt");
    size_t parentSlash = exeDir.find_last_of("\\/");
    if (parentSlash != std::string::npos) {
        std::string parentDir = exeDir.substr(0, parentSlash);
        candidates.push_back(parentDir + "\\Engine\\Build\\Build.version");
        candidates.push_back(parentDir + "\\UE4Version.txt");
        candidates.push_back(parentDir + "\\UE5Version.txt");
    }
    for (auto& path : candidates) {
        if (FileExists(path)) {
            std::string content = ReadEntireFile(path);
            if (!content.empty()) {
                content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());
                content.erase(std::remove(content.begin(), content.end(), '\n'), content.end());
                return content;
            }
        }
    }
    return "";
}

// Scans the current process memory for Unreal Engine version markers.
std::string GetVersionFromMemoryScan() {
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule)
        return "";
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
        return "";
    char* baseAddr = reinterpret_cast<char*>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;
    if (!baseAddr || moduleSize == 0)
        return "";
    std::vector<std::string> markers = { "Unreal Engine 4.", "Unreal Engine 5.", "FEngineVersion", "EngineVersion" };
    for (const auto& marker : markers) {
        size_t markerLen = marker.length();
        for (size_t i = 0; i < moduleSize - markerLen; i++) {
            if (memcmp(baseAddr + i, marker.c_str(), markerLen) == 0) {
                std::string found(marker);
                size_t maxExtra = 32;
                size_t j = i + markerLen;
                while (j < moduleSize && (j - (i + markerLen)) < maxExtra && isprint(baseAddr[j])) {
                    found.push_back(baseAddr[j]);
                    j++;
                }
                return found;
            }
        }
    }
    return "";
}

// Reads version info from a remote process by scanning its memory.
std::string GetVersionFromProcessMemory(HANDLE hProcess) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        MODULEINFO modInfo = { 0 };
        if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
            std::vector<char> buffer(modInfo.SizeOfImage);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, buffer.data(), modInfo.SizeOfImage, &bytesRead)) {
                std::vector<std::string> markers = { "Unreal Engine 4.", "Unreal Engine 5.", "FEngineVersion", "EngineVersion" };
                for (const auto& marker : markers) {
                    size_t markerLen = marker.length();
                    for (size_t i = 0; i < buffer.size() - markerLen; i++) {
                        if (memcmp(buffer.data() + i, marker.c_str(), markerLen) == 0) {
                            std::string found(marker);
                            size_t maxExtra = 32;
                            size_t j = i + markerLen;
                            while (j < buffer.size() && (j - (i + markerLen)) < maxExtra && isprint(buffer[j])) {
                                found.push_back(buffer[j]);
                                j++;
                            }
                            return found;
                        }
                    }
                }
            }
        }
    }
    return "";
}

// Checks if a process with the given executable name is running.
bool IsProcessRunning(const std::string& exeName, DWORD& processID) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (exeName == pe.szExeFile) {
                processID = pe.th32ProcessID;
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}

// Fixed prefix to allow signatures to start anywhere within/before the Gs range.
size_t adjustFoundOffsetForGroup(const std::vector<Byte>& data, size_t foundOffset, const std::string& group) {
    std::vector<std::vector<Byte>> prefixes;
    if (group == "GWorld") {
        prefixes.push_back({ 0x48, 0x89, 0x05 });
    }
    else if (group == "GNames") {
        prefixes.push_back({ 0x48, 0x8D, 0x0D }); // <= 4.27
        prefixes.push_back({ 0x48, 0x8B, 0x05 }); // > 4.27 idfk
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

// Tries to get the Unreal Engine version.
std::string GetUnrealEngineVersion(const std::string& filePath, const std::string& exeName) {
    DWORD processID = 0;
    std::string version;
    // Check if the target process is running.
    if (IsProcessRunning(exeName, processID)) {
        std::cout << "Process " << exeName << " is running (PID: " << processID << "). Attaching...\n";
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess) {
            version = GetVersionFromProcessMemory(hProcess);
            CloseHandle(hProcess);
        }
    }
    // If the version from the process is empty or just a marker, try file-based methods.
    if (version.empty() || version == "EngineVersion" || version == "FEngineVersion")
        version = GetVersionFromResource(filePath);
    if (version.empty())
        version = GetVersionFromFiles(filePath);
    if (version.empty())
        version = GetVersionFromMemoryScan();
    return version.empty() ? "Unknown" : version;
}

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

    std::string ueVersion = GetUnrealEngineVersion(gameFilePath, exeName);
    std::cout << "\nUnreal Engine Version: " << ueVersion << "\n\n";

    // File scanning
    uint64_t fileGWorld = 0, fileGNames = 0, fileGObjects = 0;
    std::vector<Signature> signatures = getSignatures();
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

    // Memory scanning.. only if file scan failed and if process is running
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

    bool missing = false;
    if ((fileGWorld == 0 && memGWorld == 0) ||
        (fileGNames == 0 && memGNames == 0) ||
        (fileGObjects == 0 && memGObjects == 0))
    {
        missing = true;
    }
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

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
