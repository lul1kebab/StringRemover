#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <thread>
#include <iomanip>

#define ID_EDIT_PID     101
#define ID_EDIT_FIND    102
#define ID_BUTTON_START 103
#define ID_OUTPUT_BOX   104
#define ID_CHECK_ADV    105

HWND hCheckAdv = nullptr;

std::string ptr_to_hex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << ptr;
    return oss.str();
}

bool TryZeroMemory(HANDLE hProc, uintptr_t addr, size_t len, std::ostringstream& log) {
    std::vector<char> zeros(len, 0);
    SIZE_T written;

    if (WriteProcessMemory(hProc, (LPVOID)addr, zeros.data(), len, &written)) {
        log << "    ✔ Write OK\n";
        return true;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        log << "    ✘ VirtualQueryEx failed\n";
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        log << "    ✘ Cannot change memory protection\n";
        return false;
    }

    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, zeros.data(), len, &written);
    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);

    log << (ok ? "    ✔ Write after protect OK\n" : "    ✘ Write failed even after protection change\n");
    return ok;
}

bool TryReadRegion(HANDLE hProc, LPCVOID base, std::vector<char>& buf, SIZE_T& readBytes) {
    if (ReadProcessMemory(hProc, base, buf.data(), buf.size(), &readBytes)) return true;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, base, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;

    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

    bool result = ReadProcessMemory(hProc, base, buf.data(), buf.size(), &readBytes);
    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    return result;
}

std::string DeleteAdvanced(DWORD pid, const std::vector<std::string>& targets) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return "ERROR: Failed to open process. Try running as Administrator.\r\n";

    SYSTEM_INFO sys;
    GetSystemInfo(&sys);

    LPCVOID addr = sys.lpMinimumApplicationAddress;
    LPCVOID max = sys.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    std::ostringstream log;
    size_t count = 0;

    for (; addr < max;) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;

        if (mbi.State == MEM_COMMIT) {
            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T readBytes = 0;

            if (TryReadRegion(hProcess, mbi.BaseAddress, buffer, readBytes)) {
                for (size_t i = 0; i < readBytes; ++i) {
                    for (const auto& target : targets) {
                        if (target.empty() || i + target.size() > readBytes) continue;
                        if (memcmp(buffer.data() + i, target.c_str(), target.size()) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i;
                            log << "[ANSI] \"" << target << "\" found at " << ptr_to_hex(found) << "\n";
                            if (TryZeroMemory(hProcess, found, target.size(), log)) {
                                count++;
                            }
                        }
                    }
                }

                // UTF-16
                const wchar_t* wbuf = (const wchar_t*)buffer.data();
                size_t wcharCount = readBytes / sizeof(wchar_t);
                for (size_t i = 0; i < wcharCount; ++i) {
                    for (const auto& target : targets) {
                        std::wstring wstr(target.begin(), target.end());
                        size_t wlen = wstr.size();
                        if (wlen == 0 || i + wlen > wcharCount) continue;
                        if (memcmp(wbuf + i, wstr.c_str(), wlen * sizeof(wchar_t)) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i * sizeof(wchar_t);
                            log << "[UTF16] \"" << target << "\" found at " << ptr_to_hex(found) << "\n";
                            if (TryZeroMemory(hProcess, found, wlen * sizeof(wchar_t), log)) {
                                count++;
                            }
                        }
                    }
                }
            }
        }

        addr = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);
    return count == 0 ? "No matches found.\r\n" : ("Deleted " + std::to_string(count) + " match(es):\r\n" + log.str());
}
std::string DeleteSimple(DWORD pid, const std::vector<std::string>& targets) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return "ERROR: Cannot open process.\r\n";

    SYSTEM_INFO sys;
    GetSystemInfo(&sys);

    LPCVOID addr = sys.lpMinimumApplicationAddress;
    LPCVOID max = sys.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::ostringstream log;
    size_t count = 0;

    for (; addr < max;) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;

        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T readBytes;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &readBytes)) {
                for (size_t i = 0; i < readBytes; ++i) {
                    for (const auto& t : targets) {
                        if (t.empty() || i + t.size() > readBytes) continue;
                        if (memcmp(buffer.data() + i, t.c_str(), t.size()) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i;
                            std::vector<char> zeros(t.size(), 0);
                            WriteProcessMemory(hProcess, (LPVOID)found, zeros.data(), t.size(), nullptr);
                            log << "Deleted \"" << t << "\" at " << ptr_to_hex(found) << "\n";
                            count++;
                        }
                    }
                }
            }
        }

        addr = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);
    return count == 0 ? "No matches found.\r\n" : ("Deleted " + std::to_string(count) + " match(es):\r\n" + log.str());
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hPidBox, hFindBox, hButton, hOutputBox;

    switch (uMsg) {
    case WM_CREATE:
        CreateWindow("STATIC", "Process ID:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hwnd, nullptr, nullptr, nullptr);
        hPidBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 10, 100, 20, hwnd, (HMENU)ID_EDIT_PID, nullptr, nullptr);

        CreateWindow("STATIC", "Target strings:", WS_VISIBLE | WS_CHILD, 10, 40, 180, 20, hwnd, nullptr, nullptr, nullptr);
        hFindBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE,
            10, 65, 310, 80, hwnd, (HMENU)ID_EDIT_FIND, nullptr, nullptr);

        hCheckAdv = CreateWindow("BUTTON", "Advanced deletion", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            10, 150, 150, 20, hwnd, (HMENU)ID_CHECK_ADV, nullptr, nullptr);

        hButton = CreateWindow("BUTTON", "Delete All", WS_VISIBLE | WS_CHILD,
            180, 145, 100, 30, hwnd, (HMENU)ID_BUTTON_START, nullptr, nullptr);

        hOutputBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
            10, 190, 330, 160, hwnd, (HMENU)ID_OUTPUT_BOX, nullptr, nullptr);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_START) {
            char pidText[32], findText[8192];
            GetWindowText(hPidBox, pidText, sizeof(pidText));
            GetWindowText(hFindBox, findText, sizeof(findText));

            DWORD pid = atoi(pidText);
            if (pid == 0 || strlen(findText) == 0) {
                MessageBox(hwnd, "Please enter valid PID and strings.", "Input Error", MB_OK | MB_ICONERROR);
                break;
            }

            std::string input(findText);
            std::replace(input.begin(), input.end(), '\r', '\n');
            std::istringstream iss(input);
            std::string line;
            std::vector<std::string> targets;
            while (std::getline(iss, line)) {
                if (!line.empty()) targets.push_back(line);
            }

            if (targets.empty()) {
                MessageBox(hwnd, "No valid strings to delete.", "Input Error", MB_OK | MB_ICONERROR);
                break;
            }

            BOOL useAdv = SendMessage(hCheckAdv, BM_GETCHECK, 0, 0) == BST_CHECKED;
            SetWindowText(hOutputBox, "Working... Please wait.\r\n");

            std::thread([=]() {
                std::string result = useAdv ? DeleteAdvanced(pid, targets) : DeleteSimple(pid, targets);
                SetWindowText(hOutputBox, result.c_str());
            }).detach();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    const char CLASS_NAME[] = "MemoryCleanerTool";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, "Memory String Deleter",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 370, 410,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
