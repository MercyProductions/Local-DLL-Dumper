#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <conio.h>
#include <filesystem>

namespace fs = std::filesystem;

// Helper function to convert TCHAR to std::string
std::string TCHARToString(const TCHAR* tchar) {
    std::wstring ws(tchar);
    return std::string(ws.begin(), ws.end());
}

// Function to enable the necessary privileges
BOOL EnablePrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else {
        tp.Privileges[0].Attributes = 0;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege. \n";
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Function to save DLL names to a file and print them to the console
void SaveDLLNamesToFileAndPrint(const std::vector<std::string>& dllNames, const std::string& baseFilename) {
    std::ofstream outfile(baseFilename);
    if (outfile.is_open()) {
        std::cout << "Saving DLL names to " << baseFilename << ":\n";
        for (const auto& name : dllNames) {
            outfile << name << std::endl;
            std::cout << name << std::endl;
        }
        outfile.close();
    }
    else {
        std::cerr << "Error opening file: " << baseFilename << std::endl;
    }
}

// Function to copy DLL files to a specified directory
void CopyDLLsToDirectory(const std::vector<std::string>& dllNames, const std::string& directory) {
    fs::create_directories(directory);
    for (const auto& dllPath : dllNames) {
        fs::path srcPath(dllPath);
        fs::path dstPath = fs::path(directory) / srcPath.filename();
        try {
            fs::copy_file(srcPath, dstPath, fs::copy_options::overwrite_existing);
            std::cout << "Copied " << srcPath.string() << " to " << dstPath.string() << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to copy " << srcPath.string() << " to " << dstPath.string() << ": " << e.what() << std::endl;
        }
    }
}

// Function to get the names of injected DLLs, including in-memory modules
std::vector<std::string> GetInjectedDLLNames(DWORD processID) {
    std::vector<std::string> dllNames;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess) {
        std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
        return dllNames;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                dllNames.push_back(TCHARToString(szModName));
            }
            else {
                std::cerr << "Failed to get module file name. Error code: " << GetLastError() << std::endl;
            }
        }
    }
    else {
        std::cerr << "Failed to enumerate process modules. Error code: " << GetLastError() << std::endl;
    }

    // Additional logic to detect in-memory DLLs
    MEMORY_BASIC_INFORMATION mbi;
    for (PBYTE address = nullptr; VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi); address += mbi.RegionSize) {
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, static_cast<HMODULE>(mbi.AllocationBase), szModName, sizeof(szModName) / sizeof(TCHAR))) {
                std::string moduleName = TCHARToString(szModName);
                if (std::find(dllNames.begin(), dllNames.end(), moduleName) == dllNames.end()) {
                    dllNames.push_back(moduleName + " (In-Memory)");
                }
            }
        }
    }

    CloseHandle(hProcess);
    return dllNames;
}

// Function to get process ID by name
DWORD GetProcessIDByName(const std::string& processName) {
    DWORD processID = 0;
    DWORD processes[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        std::cerr << "Failed to enumerate processes. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++) {
        if (processes[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                }

                std::string processNameStr = TCHARToString(szProcessName);
                if (processNameStr == processName) {
                    processID = processes[i];
                    CloseHandle(hProcess);
                    break;
                }
                CloseHandle(hProcess);
            }
            else {
                std::cerr << "Failed to open process for reading. Error code: " << GetLastError() << std::endl;
            }
        }
    }

    return processID;
}

// Function to compare two sets of DLLs and print differences
void CompareDLLSets(const std::vector<std::string>& set1, const std::vector<std::string>& set2) {
    std::vector<std::string> diff;

    // Find DLLs in set2 not in set1
    for (const auto& dll : set2) {
        if (std::find(set1.begin(), set1.end(), dll) == set1.end()) {
            diff.push_back("Scan 1 missing " + dll + " found in Scan 2");
        }
    }

    if (diff.empty()) {
        std::cout << "No differences found between the sets." << std::endl;
    }
    else {
        std::cout << "Differences between sets:" << std::endl;
        for (const auto& entry : diff) {
            std::cout << entry << std::endl;
        }
    }
}

// Function to extract a specified DLL from the process
bool ExtractDLLFromProcess(DWORD processID, const std::string& dllName, const std::string& outputFilename) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess) {
        std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool success = false;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                if (TCHARToString(szModName).find(dllName) != std::string::npos) {
                    std::ifstream src(szModName, std::ios::binary);
                    if (src.is_open()) {
                        std::ofstream dst(outputFilename, std::ios::binary);
                        if (dst.is_open()) {
                            dst << src.rdbuf();
                            success = true;
                        }
                        else {
                            std::cerr << "Failed to open output file: " << outputFilename << std::endl;
                        }
                        dst.close();
                    }
                    else {
                        std::cerr << "Failed to open source DLL: " << TCHARToString(szModName) << std::endl;
                    }
                    src.close();
                    break;
                }
            }
            else {
                std::cerr << "Failed to get module file name. Error code: " << GetLastError() << std::endl;
            }
        }
    }
    else {
        std::cerr << "Failed to enumerate process modules. Error code: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return success;
}

int main() {
    // Enable SeDebugPrivilege
    if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
        std::cerr << "Failed to enable SeDebugPrivilege" << std::endl;
        return 1;
    }

    std::string targetProcessName;
    std::cout << "Enter the name of the application (e.g., BlackOpsColdWar.exe): ";
    std::cin >> targetProcessName;

    DWORD processID = GetProcessIDByName(targetProcessName);

    if (processID == 0) {
        std::cerr << "Process " << targetProcessName << " not found." << std::endl;
        std::cout << "Press any key to exit...";
        _getch();
        return 1;
    }

    int choice;
    std::vector<std::string> dllSet1, dllSet2;

    std::cout << "Select an option:\n1. Dump DLLs 1st Set\n2. Dump DLLs 2nd Set\n3. Compare DLLs\n4. Dump DLL From Game\n";
    std::cin >> choice;

    switch (choice) {
    case 1:
        dllSet1 = GetInjectedDLLNames(processID);
        SaveDLLNamesToFileAndPrint(dllSet1, "1.txt");
        CopyDLLsToDirectory(dllSet1, "folder1");
        std::cout << "DLL names saved to 1.txt and copied to folder1" << std::endl;
        break;

    case 2:
        dllSet2 = GetInjectedDLLNames(processID);
        SaveDLLNamesToFileAndPrint(dllSet2, "2.txt");
        CopyDLLsToDirectory(dllSet2, "folder2");
        std::cout << "DLL names saved to 2.txt and copied to folder2" << std::endl;
        break;

    case 3:
        std::cout << "Comparing DLL sets..." << std::endl;
        CompareDLLSets(dllSet1, dllSet2);
        break;

    case 4: {
        std::string dllName, outputFilename;
        std::cout << "Enter the DLL name to extract: ";
        std::cin >> dllName;
        std::cout << "Enter the output filename: ";
        std::cin >> outputFilename;
        if (ExtractDLLFromProcess(processID, dllName, outputFilename)) {
            std::cout << "DLL extracted successfully to " << outputFilename << std::endl;
        }
        else {
            std::cerr << "Failed to extract DLL." << std::endl;
        }
        break;
    }

    default:
        std::cerr << "Invalid choice." << std::endl;
        break;
    }

    std::cout << "Press any key to exit...";
    _getch();
    return 0;
}
