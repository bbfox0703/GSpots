#include "UEVersionScanner.h"
#include "../GOffsets/GOffsets.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Version.lib")

// Maximum allowed sizes to avoid excessive allocations.
constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;     // 100 MB
constexpr size_t MAX_IMAGE_SIZE = 512 * 1024 * 1024;    // 512 MB

// Helper: Reads an entire file into a string.
static std::string ReadEntireFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Helper: Checks if a file exists.
static bool FileExists(const std::string& filePath) {
    DWORD attrib = GetFileAttributesA(filePath.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Helper: ensures the buffer we want to scan is large enough for the marker.
static bool CanScan(size_t bufferSize, size_t markerLen) {
    return bufferSize >= markerLen;
}

std::string GetVersionFromResource(const std::string& filePath) {
    char modulePath[MAX_PATH] = { 0 };
    errno_t pathCopyResult = strcpy_s(modulePath, filePath.c_str());
    if (pathCopyResult != 0) {
        std::cerr << "strcpy_s failed to copy file path in GetVersionFromResource\n";
        return "";
    }
    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeA(modulePath, &dummy);
    if (size == 0)
        return "";
    if (size > MAX_FILE_SIZE) {
        std::cerr << "Error: Version info resource is too large (" << size
                  << " bytes; limit is " << MAX_FILE_SIZE << ")." << std::endl;
        return "";
    }
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
        int versionResult = sprintf_s(versionStr, "%d.%d.%d.%d", major, minor, build, revision);
        if (versionResult <= 0) {
            std::cerr << "sprintf_s failed to format version string in GetVersionFromResource\n";
            return "";
        }
        return versionStr;
    }
    return "";
}

std::string GetVersionFromFiles(const std::string& filePath) {
    char modulePath[MAX_PATH] = { 0 };
    errno_t pathCopyResult = strcpy_s(modulePath, filePath.c_str());
    if (pathCopyResult != 0) {
        std::cerr << "strcpy_s failed to copy file path in GetVersionFromFiles\n";
        return "";
    }
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
        if (!CanScan(moduleSize, markerLen))
            continue;
        for (size_t i = 0; i < moduleSize - markerLen; i++) {
            if (memcmp(baseAddr + i, marker.c_str(), markerLen) == 0) {
                std::string found(marker);
                size_t maxExtra = 32;
                size_t j = i + markerLen;
                while (j < moduleSize && (j - (i + markerLen)) < maxExtra && isprint(static_cast<unsigned char>(baseAddr[j]))) {
                    found.push_back(baseAddr[j]);
                    j++;
                }
                return found;
            }
        }
    }
    return "";
}

std::string GetVersionFromProcessMemory(HANDLE hProcess) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        MODULEINFO modInfo = { 0 };
        if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
            if (modInfo.SizeOfImage > MAX_IMAGE_SIZE) {
                std::cerr << "Error: Process module size " << modInfo.SizeOfImage
                          << " bytes exceeds limit of " << MAX_IMAGE_SIZE << std::endl;
                return "";
            }
            std::vector<char> buffer(modInfo.SizeOfImage);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, buffer.data(), modInfo.SizeOfImage, &bytesRead)) {

                buffer.resize(bytesRead);

                std::vector<std::string> markers = { "Unreal Engine 4.", "Unreal Engine 5.", "FEngineVersion", "EngineVersion" };
                for (const auto& marker : markers) {
                    size_t markerLen = marker.length();
                    if (!CanScan(buffer.size(), markerLen))
                        continue;
                    for (size_t i = 0; i + markerLen <= bytesRead; i++) {
                        if (memcmp(buffer.data() + i, marker.c_str(), markerLen) == 0) {
                            std::string found(marker);
                            size_t maxExtra = 32;
                            size_t j = i + markerLen;
                            while (j < bytesRead && (j - (i + markerLen)) < maxExtra && isprint(static_cast<unsigned char>(buffer[j]))) {
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

std::string GetUnrealEngineVersion(const std::string& filePath, const std::string& exeName) {
    DWORD processID = 0;
    std::string version;
    // If the process is running, try to scan its memory first.
    if (IsProcessRunning(exeName, processID)) {
        std::cout << "Process " << exeName << " is running (PID: " << processID << "). Attaching...\n";
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess) {
            version = GetVersionFromProcessMemory(hProcess);
            CloseHandle(hProcess);
        }
    }
    // Fall back to file-based methods.
    if (version.empty() || version == "EngineVersion" || version == "FEngineVersion")
        version = GetVersionFromResource(filePath);
    if (version.empty())
        version = GetVersionFromFiles(filePath);
    if (version.empty())
        version = GetVersionFromMemoryScan();
    return version.empty() ? "Unknown" : version;
}
