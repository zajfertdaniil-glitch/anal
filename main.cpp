#include <iostream>
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>

void FastLog() { std::cout << std::unitbuf; }

std::string HexAddr(uintptr_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << addr;
    return oss.str();
}

DWORD GetPid(const char* procName) {
    std::cout << "[DBG] Searching for process: " << procName << "\n";
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cout << "[-] CreateToolhelp32Snapshot failed. Error: " << GetLastError() << "\n";
        return 0;
    }
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    int checked = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            checked++;
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                std::cout << "[DBG] Found after checking " << checked << " processes\n";
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (pid == 0) std::cout << "[DBG] Checked " << checked << " processes, not found\n";
    return pid;
}

void LogMemRegion(MEMORY_BASIC_INFORMATION& mbi) {
    std::cout << "[DBG] Region: " << HexAddr((uintptr_t)mbi.BaseAddress)
              << " Size: " << std::dec << (mbi.RegionSize / 1024) << "KB"
              << " Protect: 0x" << std::hex << mbi.Protect << std::dec << "\n";
}

void WriteRunMarker() {
    HKEY hKey;
    const char* keyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer";
    const char* valueName = "Incr3ase";
    const char* data = "";  // Empty string for REG_SZ

    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        // Try HKCU instead (no admin needed)
        res = RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_SET_VALUE, &hKey);
        if (res != ERROR_SUCCESS) {
            return;
        }
    }

    RegSetValueExA(hKey, valueName, 0, REG_SZ, (BYTE*)data, strlen(data) + 1);
    RegCloseKey(hKey);
}

void Exit() {
    std::cout << "\n[EXIT] Press ENTER...";
    std::cin.ignore(10000, '\n'); std::cin.get();
    exit(0);
}

int main() {
    FastLog();
    std::cout << "=== AGGRESSIVE WIPER v3 (32-bit GTA SA) ===\n";
    std::cout << "[DBG] Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "[DBG] sizeof(void*) = " << sizeof(void*) << " (should be 4 for 32-bit target)\n\n";

    WriteRunMarker();
    std::cout << "\n";

    const char* target = "gta_sa.exe";
    std::string pattern = "Dear ImGui";
    int wipeSize = 64;
    std::vector<char> zeros(wipeSize, 0x00);

    // 1. Get PID
    DWORD pid = GetPid(target);
    if (pid == 0) { std::cout << "[-] Process not found.\n"; Exit(); }
    std::cout << "[+] PID: " << pid << "\n\n";

    // 2. Open Process
    std::cout << "[DBG] Opening process with PROCESS_ALL_ACCESS...\n";
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cout << "[-] OpenProcess failed. Error: " << GetLastError() << " (try Admin)\n";
        Exit();
    }
    std::cout << "[+] Handle: " << hProc << "\n";

    // Get base address info
    HMODULE hMods[1024];
    DWORD cbNeeded;
    // Try to get module info via snapshot
    HANDLE hSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap2 != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(hSnap2, &me)) {
            std::cout << "[DBG] Main module: " << me.szModule
                      << " Base: " << HexAddr((uintptr_t)me.modBaseAddr)
                      << " Size: " << (me.modBaseSize / 1024) << "KB\n";
        }
        CloseHandle(hSnap2);
    }

    // 3. Scan
    unsigned char* addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int wiped = 0;
    int regionsScanned = 0;
    int regionsValid = 0;
    SIZE_T totalScannedBytes = 0;

    std::cout << "\n[*] Starting memory scan for pattern: \"" << pattern << "\"\n";
    std::cout << "[DBG] Wipe size: " << wipeSize << " bytes\n\n";

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        regionsScanned++;

        bool valid = (mbi.State == MEM_COMMIT) &&
                     (mbi.Protect == PAGE_READWRITE ||
                      mbi.Protect == PAGE_EXECUTE_READWRITE ||
                      mbi.Protect == PAGE_READONLY ||
                      mbi.Protect == PAGE_EXECUTE_READ);

        if (valid) {
            regionsValid++;
            totalScannedBytes += mbi.RegionSize;

            if (mbi.RegionSize > 1024 * 1024) { // Only log large regions
                LogMemRegion(mbi);
            }

            std::vector<char> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead)) {
                if (bytesRead != mbi.RegionSize) {
                    std::cout << "[DBG] Partial read at " << HexAddr((uintptr_t)mbi.BaseAddress)
                              << " got " << bytesRead << "/" << mbi.RegionSize << "\n";
                }

                auto it = buf.begin();
                while (true) {
                    it = std::search(it, buf.end(), pattern.begin(), pattern.end());
                    if (it == buf.end()) break;

                    size_t offset = std::distance(buf.begin(), it);
                    LPVOID targetAddr = (LPVOID)((uintptr_t)mbi.BaseAddress + offset);

                    std::cout << "[!] FOUND at " << HexAddr((uintptr_t)targetAddr)
                              << " (offset +" << std::dec << offset << " in region)\n";

                    // Show context bytes before wiping
                    std::cout << "[DBG] Context: ";
                    for (int i = 0; i < std::min((int)pattern.size() + 8, (int)(buf.end() - it)); i++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << (unsigned char)*(it + i) << " ";
                    }
                    std::cout << std::dec << "\n";

                    DWORD oldP = 0;
                    std::cout << "[DBG] Changing protection to PAGE_EXECUTE_READWRITE...\n";
                    if (VirtualProtectEx(hProc, targetAddr, wipeSize, PAGE_EXECUTE_READWRITE, &oldP)) {
                        std::cout << "[DBG] Old protect was: 0x" << std::hex << oldP << std::dec << "\n";

                        SIZE_T written = 0;
                        if (WriteProcessMemory(hProc, targetAddr, zeros.data(), wipeSize, &written)) {
                            std::cout << "[DBG] Written " << written << "/" << wipeSize << " bytes\n";
                            FlushInstructionCache(hProc, targetAddr, wipeSize);

                            // Verify
                            std::vector<char> check(wipeSize);
                            SIZE_T vread = 0;
                            ReadProcessMemory(hProc, targetAddr, check.data(), wipeSize, &vread);

                            bool clean = true;
                            int nonZero = 0;
                            for (char c : check) if (c != 0x00) { clean = false; nonZero++; }

                            if (clean) {
                                std::cout << "[+] WIPED successfully at " << HexAddr((uintptr_t)targetAddr) << "\n";
                                wiped++;
                            } else {
                                std::cout << "[-] WIPE FAILED - " << nonZero << " non-zero bytes remain\n";
                            }
                        } else {
                            std::cout << "[-] WriteProcessMemory failed. Error: " << GetLastError() << "\n";
                        }
                        VirtualProtectEx(hProc, targetAddr, wipeSize, oldP, &oldP);
                        std::cout << "[DBG] Protection restored to: 0x" << std::hex << oldP << std::dec << "\n";
                    } else {
                        std::cout << "[-] VirtualProtectEx failed. Error: " << GetLastError() << "\n";
                    }

                    it += pattern.size();
                }
            } else {
                std::cout << "[DBG] ReadProcessMemory failed at "
                          << HexAddr((uintptr_t)mbi.BaseAddress)
                          << " Error: " << GetLastError() << "\n";
            }
        }

        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);

    std::cout << "\n=== SCAN COMPLETE ===\n";
    std::cout << "[DBG] Regions scanned : " << regionsScanned << "\n";
    std::cout << "[DBG] Regions valid   : " << regionsValid << "\n";
    std::cout << "[DBG] Total scanned   : " << (totalScannedBytes / 1024 / 1024) << " MB\n";
    std::cout << "[DBG] Pattern matches : " << wiped << "\n";
    std::cout << "---------------------\n";
    std::cout << "Total Wiped: " << wiped << "\n";
    if (wiped > 0) std::cout << "[!] SUCCESS - Rescan recommended.\n";
    else std::cout << "[*] Nothing found. ImGui may not be loaded yet.\n";

    Exit();
    return 0;
}
