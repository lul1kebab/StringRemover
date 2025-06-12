#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <algorithm>
#include <iomanip>

#define ID_EDIT_PID     101
#define ID_EDIT_FIND    102
#define ID_BUTTON_START 103
#define ID_OUTPUT_BOX   104

std::string to_hex(uintptr_t addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << addr;
    return ss.str();
}

bool ZeroMemoryAt(HANDLE hProc, uintptr_t addr, size_t size) {
    std::vector<char> zero(size, 0);
    SIZE_T out;
    if (WriteProcessMemory(hProc, (LPVOID)addr, zero.data(), size, &out))
        return true;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect))
        return false;

    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, zero.data(), size, &out);
    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    return ok;
}

bool ReadMemSafe(HANDLE hProc, LPCVOID base, std::vector<char>& buf, SIZE_T& readBytes) {
    if (ReadProcessMemory(hProc, base, buf.data(), buf.size(), &readBytes))
        return true;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, base, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    DWORD old;
    if (!VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &old))
        return false;

    bool result = ReadProcessMemory(hProc, base, buf.data(), buf.size(), &readBytes);
    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, old, &old);
    return result;
}

std::string ScanAndDelete(DWORD pid, const std::vector<std::string>& strings, HWND outBox) {
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return "ERROR: Can't open process. Try running as Administrator.\r\n";

    SYSTEM_INFO info;
    GetSystemInfo(&info);

    LPCVOID addr = info.lpMinimumApplicationAddress;
    LPCVOID max  = info.lpMaximumApplicationAddress;

    std::ostringstream log;
    MEMORY_BASIC_INFORMATION mbi;
    size_t count = 0;

    while (addr < max) {
        if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        if (mbi.State == MEM_COMMIT) {
            std::vector<char> buf(mbi.RegionSize);
            SIZE_T bytes = 0;

            if (ReadMemSafe(hProc, mbi.BaseAddress, buf, bytes)) {
                // ANSI
                for (size_t i = 0; i < bytes; ++i) {
                    for (const auto& str : strings) {
                        if (str.empty() || i + str.size() > bytes) continue;
                        if (memcmp(buf.data() + i, str.c_str(), str.size()) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i;
                            if (ZeroMemoryAt(hProc, found, str.size())) {
                                log << "[ANSI] Deleted \"" << str << "\" at " << to_hex(found) << "\r\n";
                                ++count;
                            }
                        }
                    }
                }

                // UTF-16
                const wchar_t* wide = (const wchar_t*)buf.data();
                size_t chars = bytes / sizeof(wchar_t);
                for (size_t i = 0; i < chars; ++i) {
                    for (const auto& str : strings) {
                        std::wstring wstr(str.begin(), str.end());
                        if (wstr.empty() || i + wstr.size() > chars) continue;
                        if (memcmp(wide + i, wstr.c_str(), wstr.size() * sizeof(wchar_t)) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i * sizeof(wchar_t);
                            if (ZeroMemoryAt(hProc, found, wstr.size() * sizeof(wchar_t))) {
                                log << "[UTF16] Deleted \"" << str << "\" at " << to_hex(found) << "\r\n";
                                ++count;
                            }
                        }
                    }
                }
            }
        }

        addr = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProc);

    return count == 0 ? "No matches found.\r\n" : ("Deleted " + std::to_string(count) + " match(es):\r\n" + log.str());
}

// --- GUI ---

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hPidBox, hFindBox, hButton, hOutputBox;

    switch (msg) {
    case WM_CREATE:
        CreateWindow("STATIC", "Process ID:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hwnd, NULL, NULL, NULL);
        hPidBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 10, 100, 20, hwnd, (HMENU)ID_EDIT_PID, NULL, NULL);

        CreateWindow("STATIC", "Target strings:", WS_VISIBLE | WS_CHILD, 10, 40, 100, 20, hwnd, NULL, NULL, NULL);
        hFindBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL,
            10, 65, 310, 80, hwnd, (HMENU)ID_EDIT_FIND, NULL, NULL);

        hButton = CreateWindow("BUTTON", "Delete All", WS_VISIBLE | WS_CHILD, 100, 150, 100, 30, hwnd, (HMENU)ID_BUTTON_START, NULL, NULL);

        hOutputBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
            10, 190, 320, 130, hwnd, (HMENU)ID_OUTPUT_BOX, NULL, NULL);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_START) {
            char pidText[32], strText[8192];
            GetWindowText(hPidBox, pidText, sizeof(pidText));
            GetWindowText(hFindBox, strText, sizeof(strText));

            DWORD pid = atoi(pidText);
            if (pid == 0 || strlen(strText) == 0) {
                MessageBox(hwnd, "Enter valid PID and at least one string.", "Error", MB_OK | MB_ICONERROR);
                break;
            }

            std::string input(strText);
            std::replace(input.begin(), input.end(), '\r', '\n');
            std::istringstream in(input);
            std::vector<std::string> targets;
            std::string line;
            while (std::getline(in, line)) {
                if (!line.empty()) targets.push_back(line);
            }

            if (targets.empty()) {
                MessageBox(hwnd, "No valid strings.", "Error", MB_OK | MB_ICONERROR);
                break;
            }

            SetWindowText(hOutputBox, "Working...\r\n");
            std::thread([=]() {
                auto res = ScanAndDelete(pid, targets, hOutputBox);
                SetWindowText(hOutputBox, res.c_str());
            }).detach();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    const char cls[] = "MemEraseTool";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = cls;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, cls, "Memory String Deleter",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 360, 380,
        NULL, NULL, hInst, NULL);

    if (!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
