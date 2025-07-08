#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>

#define ID_EDIT_PID     101
#define ID_EDIT_FIND    102
#define ID_BUTTON_START 103
#define ID_OUTPUT_BOX   104

HWND hOutputBox = nullptr;

//———————————————————— Utilities ————————————————————

std::string ptr_to_hex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << ptr;
    return oss.str();
}

bool SetPrivilege(HANDLE hToken, LPCTSTR name) {
    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValue(nullptr, name, &tp.Privileges[0].Luid))
        return false;
    tp.PrivilegeCount              = 1;
    tp.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllDebugPrivileges() {
    HANDLE ht;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                         &ht))
    {
        const LPCTSTR privs[] = {
            SE_DEBUG_NAME,
            SE_BACKUP_NAME,
            SE_RESTORE_NAME,
            SE_TAKE_OWNERSHIP_NAME,
            SE_SECURITY_NAME
        };
        for (auto p : privs) SetPrivilege(ht, p);
        CloseHandle(ht);
    }
}

std::vector<HANDLE> SuspendAllThreads(DWORD pid) {
    std::vector<HANDLE> threads;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hs == INVALID_HANDLE_VALUE) return threads;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(hs, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME,
                                       FALSE, te.th32ThreadID);
                if (hT) {
                    SuspendThread(hT);
                    threads.push_back(hT);
                }
            }
        } while (Thread32Next(hs, &te));
    }
    CloseHandle(hs);
    return threads;
}

void ResumeAllThreads(const std::vector<HANDLE>& threads) {
    for (HANDLE hT : threads) {
        ResumeThread(hT);
        CloseHandle(hT);
    }
}

bool TryReadRegion(HANDLE hProc, LPCVOID base,
                   std::vector<char>& buf, SIZE_T& outRead)
{
    if (ReadProcessMemory(hProc, base, buf.data(),
                          buf.size(), &outRead))
        return true;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, base, &mbi, sizeof(mbi))
        != sizeof(mbi)) return false;
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
                          mbi.BaseAddress,
                          mbi.RegionSize,
                          PAGE_EXECUTE_READWRITE,
                          &oldProt))
        return false;
    bool ok = ReadProcessMemory(hProc, base,
                                buf.data(),
                                buf.size(),
                                &outRead);
    VirtualProtectEx(hProc,
                     mbi.BaseAddress,
                     mbi.RegionSize,
                     oldProt,
                     &oldProt);
    return ok;
}

bool TryZeroMemory(HANDLE hProc, uintptr_t addr, size_t len,
                   std::ostringstream& log)
{
    std::vector<char> zeros(len, 0);
    SIZE_T written = 0;
    if (WriteProcessMemory(hProc, (LPVOID)addr,
                           zeros.data(), len, &written))
    {
        log << "    ✔ Write OK\n";
        FlushInstructionCache(hProc,
                              (LPCVOID)addr,
                              len);
        return true;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc,
                       (LPCVOID)addr,
                       &mbi, sizeof(mbi))
        != sizeof(mbi))
    {
        log << "    ✘ VirtualQueryEx failed\n";
        return false;
    }
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
                          mbi.BaseAddress,
                          mbi.RegionSize,
                          PAGE_EXECUTE_READWRITE,
                          &oldProt))
    {
        log << "    ✘ Protect change failed\n";
        return false;
    }
    bool ok = WriteProcessMemory(hProc,
                                 (LPVOID)addr,
                                 zeros.data(),
                                 len,
                                 &written);
    FlushInstructionCache(hProc, (LPCVOID)addr, len);
    VirtualProtectEx(hProc,
                     mbi.BaseAddress,
                     mbi.RegionSize,
                     oldProt,
                     &oldProt);
    log << (ok
            ? "    ✔ Write after protect OK\n"
            : "    ✘ Write after protect failed\n");
    return ok;
}

bool SafeZeroNoSuspend(HANDLE hProc,
                       uintptr_t addr,
                       size_t len,
                       std::ostringstream& log)
{
    std::vector<char> zeros(len, 0);
    SIZE_T written = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc,
                       (LPCVOID)addr,
                       &mbi, sizeof(mbi))
        != sizeof(mbi))
    {
        log << "    ✘ Query failed\n";
        return false;
    }
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
                          mbi.BaseAddress,
                          mbi.RegionSize,
                          PAGE_EXECUTE_READWRITE,
                          &oldProt))
    {
        log << "    ✘ Protect failed\n";
        return false;
    }
    if (WriteProcessMemory(hProc,
                           (LPVOID)addr,
                           zeros.data(),
                           len,
                           &written))
    {
        log << "    ✔ Zeroed " << written << " bytes\n";
    }
    else {
        log << "    ✘ Write failed (" << GetLastError() << ")\n";
    }
    FlushInstructionCache(hProc,
                          (LPCVOID)addr,
                          len);
    VirtualProtectEx(hProc,
                     mbi.BaseAddress,
                     mbi.RegionSize,
                     oldProt,
                     &oldProt);
    return written == len;
}

//———————————————————— Advanced deletion ————————————————————

std::string DeleteAdvanced(DWORD pid,
                           const std::vector<std::string>& targets)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,
                               FALSE, pid);
    if (!hProc)
        return "ERROR: Cannot open process. Try Admin.\r\n";

    EnableAllDebugPrivileges();
    auto suspended = SuspendAllThreads(pid);

    // collect COMMIT regions
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    SYSTEM_INFO sys; GetSystemInfo(&sys);
    uintptr_t addr = (uintptr_t)sys.lpMinimumApplicationAddress;
    uintptr_t max  = (uintptr_t)sys.lpMaximumApplicationAddress;
    while (addr < max) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc,
                           (LPCVOID)addr,
                           &mbi, sizeof(mbi))
            != sizeof(mbi))
            break;
        if (mbi.State == MEM_COMMIT)
            regions.push_back(mbi);
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    std::ostringstream log;
    std::mutex      mtx;
    std::atomic<size_t> idx{0}, total{0};
    size_t n = regions.size();
    unsigned workers = std::thread::hardware_concurrency();
    if (!workers) workers = 4;

    auto worker = [&](){
        while (true) {
            size_t i = idx.fetch_add(1);
            if (i >= n) break;
            auto& mbi = regions[i];

            std::vector<char> buf(mbi.RegionSize);
            SIZE_T rb = 0;
            if (!TryReadRegion(hProc,
                               mbi.BaseAddress,
                               buf, rb))
                continue;

            // ANSI
            for (size_t off = 0; off + 1 < rb; ++off) {
                for (auto& t : targets) {
                    size_t len = t.size();
                    if (!len || off + len > rb) continue;
                    if (memcmp(buf.data()+off,
                               t.c_str(), len)==0)
                    {
                        uintptr_t f = (uintptr_t)mbi.BaseAddress + off;
                        std::ostringstream e;
                        e<<"[ANSI] \""<<t<<"\" at "
                         <<ptr_to_hex(f)<<"\n";
                        if (mbi.Type == MEM_PRIVATE)
                            SafeZeroNoSuspend(hProc, f, len, e);
                        else
                            TryZeroMemory(hProc, f, len, e);
                        e<<"\n";
                        {
                            std::lock_guard<std::mutex> lk(mtx);
                            log<<e.str();
                        }
                        total++;
                    }
                }
            }
            // UTF-16LE
            size_t wc = rb/sizeof(wchar_t);
            auto wptr = (const wchar_t*)buf.data();
            for (size_t off=0; off+1<wc; ++off) {
                for (auto& t : targets) {
                    std::wstring ws(t.begin(), t.end());
                    size_t wl = ws.size();
                    if (!wl || off+wl>wc) continue;
                    if (memcmp(wptr+off,
                               ws.c_str(),
                               wl*sizeof(wchar_t))==0)
                    {
                        uintptr_t f = (uintptr_t)mbi.BaseAddress
                                      + off*sizeof(wchar_t);
                        std::ostringstream e;
                        e<<"[UTF16] \""<<t<<"\" at "
                         <<ptr_to_hex(f)<<"\n";
                        if (mbi.Type == MEM_PRIVATE)
                            SafeZeroNoSuspend(hProc,
                                              f,
                                              wl*sizeof(wchar_t),
                                              e);
                        else
                            TryZeroMemory(hProc,
                                         f,
                                         wl*sizeof(wchar_t),
                                         e);
                        e<<"\n";
                        {
                            std::lock_guard<std::mutex> lk(mtx);
                            log<<e.str();
                        }
                        total++;
                    }
                }
            }
        }
    };

    // start worker threads
    std::vector<std::thread> th;
    for (unsigned i=0; i<workers; ++i)
        th.emplace_back(worker);
    for (auto& t : th) t.join();

    ResumeAllThreads(suspended);
    CloseHandle(hProc);

    size_t cnt = total.load();
    if (!cnt) return "No matches found.\r\n";
    return "Deleted "+std::to_string(cnt)
           +" match(es):\r\n"+log.str();
}

//———————————————————— GUI ————————————————————

LRESULT CALLBACK WindowProc(HWND hwnd,
                            UINT msg,
                            WPARAM wp,
                            LPARAM lp)
{
    static HWND hPid, hFind, hBtn;
    switch (msg) {
    case WM_CREATE:
        CreateWindow("STATIC","Process ID:",
                     WS_VISIBLE|WS_CHILD,
                     10,10,80,20,
                     hwnd,nullptr,nullptr,nullptr);
        hPid = CreateWindow("EDIT","",
                            WS_VISIBLE|WS_CHILD|WS_BORDER,
                            100,10,100,20,
                            hwnd,(HMENU)ID_EDIT_PID,nullptr,nullptr);

        CreateWindow("STATIC","Target strings:",
                     WS_VISIBLE|WS_CHILD,
                     10,40,120,20,
                     hwnd,nullptr,nullptr,nullptr);
        hFind = CreateWindow("EDIT","",
                             WS_VISIBLE|WS_CHILD|WS_BORDER|
                             WS_VSCROLL|ES_MULTILINE,
                             10,65,310,80,
                             hwnd,(HMENU)ID_EDIT_FIND,nullptr,nullptr);

        hBtn = CreateWindow("BUTTON","Delete All",
                            WS_VISIBLE|WS_CHILD,
                            180,160,100,30,
                            hwnd,(HMENU)ID_BUTTON_START,nullptr,nullptr);

        hOutputBox = CreateWindow("EDIT","",
            WS_VISIBLE|WS_CHILD|WS_BORDER|
            WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL,
            10,200,330,160,
            hwnd,(HMENU)ID_OUTPUT_BOX,nullptr,nullptr);
        break;

    case WM_COMMAND:
        if (LOWORD(wp)==ID_BUTTON_START) {
            char pidBuf[32], findBuf[8192];
            GetWindowText(hPid, pidBuf, sizeof(pidBuf));
            GetWindowText(hFind, findBuf, sizeof(findBuf));
            DWORD pid = strtoul(pidBuf,nullptr,0);
            if (!pid || !findBuf[0]) {
                MessageBox(hwnd,
                    "Enter valid PID and at least one string.",
                    "Input Error",
                    MB_OK|MB_ICONERROR);
                break;
            }
            std::string s(findBuf);
            for (char& c : s) if (c=='\r') c='\n';
            std::istringstream iss(s);
            std::vector<std::string> targets;
            for (std::string line; std::getline(iss,line); )
                if (!line.empty()) targets.push_back(line);
            if (targets.empty()) {
                MessageBox(hwnd,
                    "No valid target strings.",
                    "Input Error",
                    MB_OK|MB_ICONERROR);
                break;
            }
            SetWindowText(hOutputBox,"Working... please wait.\r\n");
            std::thread([=](){
                std::string res = DeleteAdvanced(pid, targets);
                SetWindowText(hOutputBox, res.c_str());
            }).detach();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

int WINAPI WinMain(HINSTANCE hI,
                   HINSTANCE,
                   LPSTR,
                   int nCmd)
{
    EnableAllDebugPrivileges();
    const char CN[] = "MemoryCleaner";
    WNDCLASS wc = {};
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hI;
    wc.lpszClassName = CN;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClass(&wc);

    HWND w = CreateWindowEx(
        0, CN, "Memory String Deleter",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        370, 440,
        nullptr, nullptr, hI, nullptr
    );
    if (!w) return 0;
    ShowWindow(w,nCmd);
    UpdateWindow(w);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
