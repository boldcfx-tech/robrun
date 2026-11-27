// instant_loot.cpp  —  build x64, run as admin
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <commctrl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include <utility>
#include <algorithm>
#include <deque>
#include <thread>
#include <atomic>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")

// ------------------------------------------------------------------ config
static const wchar_t* DEFAULT_KEYWORD = L"ROB RUN";

#define USE_SIGNATURE   1

static const char* BUPDATER_PATTERN_64 = "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ??";
static const int   BUPDATER_PATTERN_OFFSET_64 = 3;

static const char* BUPDATER_PATTERN_32 = "8B 05 ?? ?? ?? ?? 8B 88 ?? ?? ?? ??";
static const int   BUPDATER_PATTERN_OFFSET_32 = 2;

static const bool BUPDATER_PATTERN_DEREF = true;

static const uintptr_t BUPDATER_STATIC_RVA = 0x0000000;

static const DWORD WATCH_INTERVAL = 100;

// entity types
enum { T_PLAYER = 0, T_CONTAINER = 1, T_LOOT = 2, T_VEHICLE = 3, T_DOOR = 4 };

struct Config
{
    bool esp            = false;
    bool aim            = false;
    bool instantLoot    = true;
    bool aimHoldMode    = true;   // true = hold aim key, false = aim always on when aim enabled

    bool drawBox        = true;
    bool drawDist       = true;
    bool drawSnapline   = false;
    bool drawPlayers    = true;
    bool drawContainers = false;
    bool drawLoot       = false;
    bool drawDoors      = false;

    int  aimFov  = 130;           // px radius around crosshair
    int  smooth  = 22;            // 1..100, lower = faster
    int  espFov  = 60;            // vertical FOV used for projection, tune to the game
    int  maxDist = 250;

    int  menuKey  = VK_RSHIFT;
    int  espKey   = VK_F1;
    int  aimKey   = VK_F2;
    int  holdKey  = VK_XBUTTON2;

    int  playerModelOff = 0x18;
    int  playerListOff  = 0x28;
    int  playerPosOff   = 0x28;
    int  playerHeightX10 = 18;    // 1.8 units
};
static Config cfg;

// ------------------------------------------------------------------ state
static HANDLE    g_proc = nullptr;
static uintptr_t g_base = 0;
static size_t    g_size = 0;
static wchar_t   g_procName[MAX_PATH] = L"";
static size_t    g_ptrSize = 8;
static bool      g_haveQI = false;
static uintptr_t g_forcedBase = 0;

static std::atomic<uintptr_t> g_bu{ 0 };
static std::atomic<bool>      g_running{ true };

struct FilePeInfo
{
    bool      ok = false;
    size_t    sizeOfImage = 0;
    uintptr_t imageBase = 0;
    WORD      machine = 0;
    wchar_t   path[MAX_PATH * 2]{};
};
static FilePeInfo g_file;

typedef NTSTATUS (NTAPI* PFN_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* PFN_NtQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
static PFN_NtReadVirtualMemory  g_ntRead = nullptr;
static PFN_NtQueryVirtualMemory g_ntQueryVm = nullptr;

static void loadNt()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return;
    g_ntRead    = reinterpret_cast<PFN_NtReadVirtualMemory>(GetProcAddress(nt, "NtReadVirtualMemory"));
    g_ntQueryVm = reinterpret_cast<PFN_NtQueryVirtualMemory>(GetProcAddress(nt, "NtQueryVirtualMemory"));
}

// ------------------------------------------------------------------ memory
static bool readRaw(uintptr_t addr, void* buf, size_t len)
{
    SIZE_T got = 0;
    if (ReadProcessMemory(g_proc, reinterpret_cast<LPCVOID>(addr), buf, len, &got) && got == len)
        return true;
    got = 0;
    if (g_ntRead && g_ntRead(g_proc, reinterpret_cast<PVOID>(addr), buf, len, &got) >= 0 && got == len)
        return true;
    return false;
}

template <typename T>
static T read(uintptr_t addr)
{
    T out{};
    if (!readRaw(addr, &out, sizeof(T))) out = T{};
    return out;
}

template <typename T>
static bool write(uintptr_t addr, T value)
{
    SIZE_T put = 0;
    return WriteProcessMemory(g_proc, reinterpret_cast<LPVOID>(addr), &value, sizeof(T), &put)
           && put == sizeof(T);
}

static bool readPtr(uintptr_t addr, uintptr_t* out)
{
    if (g_ptrSize == 4)
    {
        const uint32_t v = read<uint32_t>(addr);
        *out = v;
        return v != 0;
    }
    const uint64_t v = read<uint64_t>(addr);
    *out = static_cast<uintptr_t>(v);
    return v != 0;
}

static bool queryRegion(uintptr_t addr, MEMORY_BASIC_INFORMATION* mbi)
{
    if (g_ntQueryVm)
    {
        SIZE_T got = 0;
        if (g_ntQueryVm(g_proc, reinterpret_cast<PVOID>(addr), 0, mbi, sizeof(*mbi), &got) >= 0)
            return true;
    }
    return VirtualQueryEx(g_proc, reinterpret_cast<LPCVOID>(addr), mbi, sizeof(*mbi)) == sizeof(*mbi);
}

// ------------------------------------------------------------------ elevation
static bool isElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD cb = sizeof(el);
    bool elev = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb) && el.TokenIsElevated;
    CloseHandle(tok);
    return elev;
}

static bool relaunchElevated()
{
    wchar_t exe[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return false;

    std::wstring params;
    for (int i = 1; i < __argc; ++i) { params += L'"'; params += __wargv[i]; params += L"\" "; }

    SHELLEXECUTEINFOW sei{ sizeof(sei) };
    sei.fMask   = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb  = L"runas";
    sei.lpFile  = exe;
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.nShow   = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) return false;
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return true;
}

static bool enableDebugPrivilege()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) { CloseHandle(tok); return false; }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    bool ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

// ------------------------------------------------------------------ process
struct Cand { DWORD pid; std::wstring exe; std::wstring title; };

static std::wstring normalize(const wchar_t* s)
{
    std::wstring out;
    for (const wchar_t* p = s; *p; ++p)
        if (iswalnum(*p)) out.push_back(static_cast<wchar_t>(towlower(*p)));
    return out;
}

static bool wcontains(const std::wstring& hay, const std::wstring& needle)
{
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        if (hay.compare(i, needle.size(), needle) == 0) return true;
    return false;
}

static std::vector<std::pair<DWORD, std::wstring>> windowTitles()
{
    std::vector<std::pair<DWORD, std::wstring>> out;
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* v = reinterpret_cast<std::vector<std::pair<DWORD, std::wstring>>*>(lp);
        if (!IsWindowVisible(h) || GetWindow(h, GW_OWNER) != nullptr) return TRUE;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (!pid) return TRUE;
        wchar_t buf[512]{};
        GetWindowTextW(h, buf, 511);
        if (!buf[0]) return TRUE;
        for (auto& e : *v) if (e.first == pid) return TRUE;
        v->push_back({ pid, buf });
        return TRUE;
    }, reinterpret_cast<LPARAM>(&out));
    return out;
}

static std::vector<Cand> snapshotProcs(bool withTitles)
{
    std::vector<Cand> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        if (pe.th32ProcessID != GetCurrentProcessId())
            out.push_back({ pe.th32ProcessID, pe.szExeFile, L"" });

    CloseHandle(snap);

    if (withTitles)
    {
        auto titles = windowTitles();
        for (auto& c : out)
            for (auto& t : titles)
                if (t.first == c.pid) { c.title = t.second; break; }
        std::vector<Cand> win;
        for (auto& c : out) if (!c.title.empty()) win.push_back(c);
        return win;
    }
    return out;
}

static void printList()
{
    printf("pid      exe                             title\n");
    printf("---------------------------------------------------------------\n");
    for (auto& c : snapshotProcs(true))
        printf("%-8lu %-31ls %.60ls\n", c.pid, c.exe.c_str(), c.title.c_str());
    printf("\nusage: instant_loot.exe <exe name | --pid N> [--watch|--loot|--diag]\n");
}

static DWORD findPidExact(const wchar_t* name)
{
    for (auto& c : snapshotProcs(false))
        if (_wcsicmp(c.exe.c_str(), name) == 0) return c.pid;
    return 0;
}

static int scoreMatch(const std::wstring& exe, const std::wstring& title, const std::wstring& key)
{
    int s = 0;
    if (exe == key || exe == key + L"exe") s = 100;
    else if (exe.rfind(key, 0) == 0)       s = 60;
    else if (wcontains(exe, key))          s = 40;
    if (wcontains(title, key)) s = (std::max)(s, 5);
    return s;
}

static DWORD findPidKeyword(const wchar_t* keyword)
{
    const std::wstring key = normalize(keyword);
    if (key.empty()) return 0;

    std::vector<Cand> hits;
    std::vector<int>  scores;

    for (auto& c : snapshotProcs(true))
    {
        int s = scoreMatch(normalize(c.exe.c_str()), normalize(c.title.c_str()), key);
        if (s > 0) { hits.push_back(c); scores.push_back(s); }
    }
    if (hits.empty()) return 0;

    const int best = *std::max_element(scores.begin(), scores.end());

    std::vector<size_t> top;
    for (size_t i = 0; i < hits.size(); ++i)
        if (scores[i] == best) top.push_back(i);

    if (top.size() == 1)
    {
        wcscpy_s(g_procName, hits[top[0]].exe.c_str());
        return hits[top[0]].pid;
    }

    printf("[?] %zu equally-good matches for \"%ls\" - pick one with --pid:\n", top.size(), keyword);
    for (size_t i : top)
        printf("    %lu  %-31ls %.60ls\n", hits[i].pid, hits[i].exe.c_str(), hits[i].title.c_str());
    return 0;
}

static bool exeNameForPid(DWORD pid)
{
    for (auto& c : snapshotProcs(false))
        if (c.pid == pid) { wcscpy_s(g_procName, c.exe.c_str()); return true; }
    return false;
}

// ------------------------------------------------------------------ handle
static bool openTarget(DWORD pid)
{
    struct { const char* label; DWORD rights; bool qi; } tries[] = {
        { "rw+q", PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, true },
        { "rw+ql", PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, false },
        { "r+ql", PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false },
    };

    for (auto& t : tries)
    {
        g_proc = OpenProcess(t.rights, FALSE, pid);
        if (g_proc)
        {
            g_haveQI = t.qi;
            printf("[+] handle 0x%08lX (%s)%s\n", t.rights, t.label, t.qi ? "" : " - no QUERY_INFORMATION");
            return true;
        }
        printf("[!] OpenProcess(0x%08lX) failed (%lu)\n", t.rights, GetLastError());
    }
    return false;
}

// ------------------------------------------------------------------ file PE info
static void readFilePeInfo()
{
    g_file = FilePeInfo{};

    DWORD len = static_cast<DWORD>(_countof(g_file.path));
    if (!QueryFullProcessImageNameW(g_proc, 0, g_file.path, &len))
    {
        printf("[!] QueryFullProcessImageName failed (%lu)\n", GetLastError());
        return;
    }
    printf("[+] image path: %ls\n", g_file.path);

    HANDLE f = CreateFileW(g_file.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
    {
        printf("[!] cannot open image on disk (%lu)\n", GetLastError());
        return;
    }

    IMAGE_DOS_HEADER dos{};
    DWORD got = 0;
    if (ReadFile(f, &dos, sizeof(dos), &got, nullptr) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        SetFilePointer(f, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
    {
        IMAGE_NT_HEADERS64 nt{};
        if (ReadFile(f, &nt, sizeof(nt), &got, nullptr) && nt.Signature == IMAGE_NT_SIGNATURE)
        {
            g_file.ok          = true;
            g_file.machine     = nt.FileHeader.Machine;
            g_file.imageBase   = static_cast<uintptr_t>(nt.OptionalHeader.ImageBase);
            g_file.sizeOfImage = nt.OptionalHeader.SizeOfImage;
        }
    }
    CloseHandle(f);

    if (!g_file.ok) { printf("[!] could not parse image headers from disk\n"); return; }

    printf("[+] image base 0x%llX  size 0x%zX  machine 0x%04X\n",
           static_cast<unsigned long long>(g_file.imageBase), g_file.sizeOfImage, g_file.machine);

    if (g_file.machine == IMAGE_FILE_MACHINE_I386)       g_ptrSize = 4;
    else if (g_file.machine == IMAGE_FILE_MACHINE_AMD64) g_ptrSize = 8;
    else if (g_file.machine == IMAGE_FILE_MACHINE_ARM64) g_ptrSize = 8;
}

// ------------------------------------------------------------------ base selection
static bool plausibleBase(uintptr_t base)
{
    return base != 0 && (base & 0xFFF) == 0 && base < 0x00007FFFFFFF0000ULL;
}

static bool moduleNameAt(uintptr_t addr)
{
    wchar_t path[MAX_PATH * 2]{};
    if (!GetMappedFileNameW(g_proc, reinterpret_cast<LPVOID>(addr), path, _countof(path)))
        return false;
    const wchar_t* tail = wcsrchr(path, L'\\');
    tail = tail ? tail + 1 : path;
    return _wcsicmp(tail, g_procName) == 0;
}

static bool probeHeader(uintptr_t base)
{
    IMAGE_DOS_HEADER dos{};
    if (!readRaw(base, &dos, sizeof(dos))) return false;
    return dos.e_magic == IMAGE_DOS_SIGNATURE;
}

static bool baseFromToolhelp(DWORD pid, DWORD* err)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { *err = GetLastError(); return false; }

    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
    {
        if (_wcsicmp(me.szModule, g_procName) != 0) continue;
        const uintptr_t base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        if (!plausibleBase(base)) continue;
        g_base = base;
        if (!g_size) g_size = me.modBaseSize;
        found = true;
        break;
    }
    CloseHandle(snap);
    return found;
}

static bool baseFromPsapi(DWORD* err)
{
    HMODULE mods[512]{};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(g_proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
    {
        *err = GetLastError();
        return false;
    }
    if (needed < sizeof(HMODULE) || !mods[0]) { *err = ERROR_NOT_FOUND; return false; }

    const uintptr_t base = reinterpret_cast<uintptr_t>(mods[0]);
    if (!plausibleBase(base)) { *err = ERROR_BAD_FORMAT; return false; }

    g_base = base;
    return true;
}

static bool baseFromPeb(DWORD* err)
{
    using NtQIP = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntqip = reinterpret_cast<NtQIP>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntqip) { *err = ERROR_PROC_NOT_FOUND; return false; }

    uintptr_t peb = 0;
    uintptr_t ldrOff, listOff, linksOff, dllBaseOff, nameLenOff, nameBufOff;

    if (g_ptrSize == 4)
    {
        ULONG_PTR peb32 = 0;
        if (ntqip(g_proc, 26, &peb32, sizeof(peb32), nullptr) < 0) { *err = ERROR_BAD_FORMAT; return false; }
        if (!peb32) { *err = ERROR_BAD_FORMAT; return false; }
        peb = static_cast<uintptr_t>(peb32);
        ldrOff = 0x0C; listOff = 0x14; linksOff = 0x08;
        dllBaseOff = 0x18; nameLenOff = 0x2C; nameBufOff = 0x30;
    }
    else
    {
        PROCESS_BASIC_INFORMATION pbi{};
        if (ntqip(g_proc, 0, &pbi, sizeof(pbi), nullptr) < 0) { *err = ERROR_BAD_FORMAT; return false; }
        if (!pbi.PebBaseAddress) { *err = ERROR_BAD_FORMAT; return false; }
        peb = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
        ldrOff = 0x18; listOff = 0x20; linksOff = 0x10;
        dllBaseOff = 0x30; nameLenOff = 0x58; nameBufOff = 0x60;
    }

    uintptr_t ldr = 0;
    if (!readPtr(peb + ldrOff, &ldr)) { *err = ERROR_PARTIAL_COPY; return false; }

    const uintptr_t head = ldr + listOff;
    uintptr_t cur = 0;
    if (!readPtr(head, &cur)) { *err = ERROR_PARTIAL_COPY; return false; }

    for (int i = 0; i < 512 && cur && cur != head; ++i)
    {
        const uintptr_t entry = cur - linksOff;
        uintptr_t dllBase = 0;
        uintptr_t nameBuf = 0;
        const USHORT nameLen = read<USHORT>(entry + nameLenOff);

        if (readPtr(entry + dllBaseOff, &dllBase) && dllBase &&
            nameLen && nameLen < 512 &&
            readPtr(entry + nameBufOff, &nameBuf) && nameBuf)
        {
            wchar_t name[256]{};
            if (readRaw(nameBuf, name, nameLen))
            {
                name[nameLen / sizeof(wchar_t)] = L'\0';
                if (_wcsicmp(name, g_procName) == 0 && plausibleBase(dllBase))
                {
                    g_base = dllBase;
                    return true;
                }
            }
        }
        readPtr(cur, &cur);
    }

    *err = ERROR_NOT_FOUND;
    return false;
}

static bool baseFromImageScan(DWORD* err)
{
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    uintptr_t byName = 0;
    uintptr_t lowest = 0;

    while (queryRegion(addr, &mbi))
    {
        if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT && mbi.AllocationBase)
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            if (plausibleBase(base))
            {
                if (!byName && moduleNameAt(base)) byName = base;
                if (!lowest || base < lowest) lowest = base;
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    if (byName) { g_base = byName; return true; }
    if (lowest) { g_base = lowest; return true; }

    *err = ERROR_NOT_FOUND;
    return false;
}

static bool resolveModuleBase(DWORD pid)
{
    if (g_forcedBase)
    {
        g_base = g_forcedBase;
        printf("[+] base forced to %p\n", (void*)g_base);
        return true;
    }

    DWORD err = 0;

    if (g_haveQI && baseFromToolhelp(pid, &err)) { printf("[+] base via toolhelp\n"); return true; }
    printf("[.] toolhelp failed (err %lu)\n", err);

    err = 0;
    if (g_haveQI && baseFromPsapi(&err)) { printf("[+] base via psapi\n"); return true; }
    printf("[.] psapi failed (err %lu)\n", err);

    err = 0;
    if (baseFromPeb(&err)) { printf("[+] base via PEB walk\n"); return true; }
    printf("[.] peb walk failed (err %lu)\n", err);

    err = 0;
    if (baseFromImageScan(&err)) { printf("[+] base via image scan\n"); return true; }
    printf("[.] image scan failed (err %lu)\n", err);

    return false;
}

// ------------------------------------------------------------------ pattern
static bool parsePattern(const char* in, std::vector<int>& out)
{
    out.clear();
    for (const char* p = in; *p; )
    {
        if (*p == ' ') { ++p; continue; }
        if (p[0] == '?' && p[1] == '?') { out.push_back(-1); p += 2; continue; }
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(p[0]);
        int lo = p[1] ? nib(p[1]) : -1;
        if (hi < 0 || lo < 0) return false;
        out.push_back((hi << 4) | lo);
        p += 2;
    }
    return !out.empty();
}

static uintptr_t scanPattern(const std::vector<int>& pat)
{
    if (!g_base || !g_size) return 0;

    std::vector<uint8_t> buf(g_size);
    if (!readRaw(g_base, buf.data(), g_size)) return 0;

    const size_t n = pat.size();
    if (g_size < n) return 0;

    for (size_t i = 0; i + n <= g_size; ++i)
    {
        bool hit = true;
        for (size_t j = 0; j < n; ++j)
        {
            if (pat[j] >= 0 && buf[i + j] != static_cast<uint8_t>(pat[j])) { hit = false; break; }
        }
        if (hit) return g_base + i;
    }
    return 0;
}

static uintptr_t findBattleUpdater(bool verbose)
{
#if USE_SIGNATURE
    const bool is32 = (g_ptrSize == 4);
    const char* src = is32 ? BUPDATER_PATTERN_32 : BUPDATER_PATTERN_64;

    std::vector<int> pat;
    if (!parsePattern(src, pat)) { printf("[!] bad pattern\n"); return 0; }

    uintptr_t hit = scanPattern(pat);
    if (!hit) { if (verbose) printf("[!] pattern not found\n"); return 0; }

    if (is32)
    {
        const uint32_t abs = read<uint32_t>(hit + BUPDATER_PATTERN_OFFSET_32);
        if (!abs) return 0;
        return BUPDATER_PATTERN_DEREF ? static_cast<uintptr_t>(read<uint32_t>(abs)) : abs;
    }

    const int32_t disp = read<int32_t>(hit + BUPDATER_PATTERN_OFFSET_64);
    const uintptr_t slot = hit + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(disp));
    return BUPDATER_PATTERN_DEREF ? static_cast<uintptr_t>(read<uint64_t>(slot)) : slot;
#else
    if (!BUPDATER_STATIC_RVA) { printf("[!] set BUPDATER_STATIC_RVA\n"); return 0; }
    return read<uintptr_t>(g_base + BUPDATER_STATIC_RVA);
#endif
}

// ------------------------------------------------------------------ patch
static void InstantLoot(uintptr_t battleUpdater)
{
    if (!battleUpdater) return;

    uintptr_t content = 0;
    if (!readPtr(battleUpdater + 0x68, &content)) return;

    uintptr_t inst = 0;
    if (!readPtr(content + 0x540, &inst)) return;

    write<float>(inst + 0x58, 0.0001f);

    uintptr_t list = 0;
    if (!readPtr(inst + 0x18, &list)) return;

    uintptr_t items = 0;
    if (!readPtr(list + 0x10, &items)) return;

    const int size = read<int>(list + 0x18);
    if (size <= 0 || size > 500) return;

    for (int i = 0; i < size; ++i)
    {
        const uintptr_t pair = items + 0x20 + (static_cast<uintptr_t>(i) * 0x18);
        uintptr_t desc = 0;
        if (!readPtr(pair + 0x10, &desc)) continue;
        write<float>(desc + 0x40, 0.0f);
        write<float>(desc + 0x68, 0.0f);
    }
}

// ------------------------------------------------------------------ loot dump
static void dumpList(const char* label, uintptr_t world, uintptr_t listOff, uintptr_t posOff)
{
    uintptr_t list = 0;
    if (!readPtr(world + listOff, &list)) { printf("  %s: no list\n", label); return; }

    uintptr_t items = 0;
    if (!readPtr(list + 0x10, &items)) { printf("  %s: empty\n", label); return; }

    const int size = read<int>(list + 0x18);
    if (size <= 0 || size > 4096) { printf("  %s: bad size %d\n", label, size); return; }

    printf("  %s: %d entries\n", label, size);
    for (int i = 0; i < size; ++i)
    {
        uintptr_t ent = 0;
        if (!readPtr(items + 0x20 + (static_cast<uintptr_t>(i) * g_ptrSize), &ent)) continue;

        uintptr_t pos = 0;
        if (!readPtr(ent + posOff, &pos)) continue;

        printf("    [%3d] %11.2f %11.2f %11.2f\n",
               i, read<float>(pos + 0x10), read<float>(pos + 0x14), read<float>(pos + 0x18));
    }
}

static void DumpLoot(uintptr_t battleUpdater)
{
    if (!battleUpdater) { printf("[!] no battleUpdater\n"); return; }

    uintptr_t entities = 0;
    if (!readPtr(battleUpdater + 0x18, &entities)) { printf("[!] no battleEntitiesModel\n"); return; }

    uintptr_t world = 0;
    if (!readPtr(entities + 0x60, &world)) { printf("[!] no worldEntitiesModel\n"); return; }

    dumpList("containers",  world, 0x20, 0x28);
    dumpList("loots",       world, 0x38, 0x28);
    dumpList("vehicleLoot", world, 0x40, 0x28);
    dumpList("doors",       world, 0x48, 0x38);
}

// ------------------------------------------------------------------ diag
static void diag(DWORD pid)
{
    printf("=== diag pid %lu ===\n", pid);
    printf("elevated: %d\n", isElevated() ? 1 : 0);
    printf("SeDebugPrivilege: %d\n", enableDebugPrivilege() ? 1 : 0);

    if (!openTarget(pid)) { printf("no handle\n"); return; }
    loadNt();

    if (g_file.ok) printf("image: %ls base 0x%llX size 0x%zX\n",
                          g_file.path, static_cast<unsigned long long>(g_file.imageBase), g_file.sizeOfImage);

    if (plausibleBase(g_base))
    {
        uint8_t mz[2]{};
        const bool headerOk = readRaw(g_base, mz, sizeof(mz)) && mz[0] == 'M' && mz[1] == 'Z';
        printf("base 0x%llX: header %s\n", static_cast<unsigned long long>(g_base),
               headerOk ? "intact" : "ERASED");
        printf("module name at base: %d\n", moduleNameAt(g_base) ? 1 : 0);
    }

    CloseHandle(g_proc);
    g_proc = nullptr;
}

// ==================================================================
//  GUI / overlay / ESP / aim
// ==================================================================

struct Vec3 { float x, y, z; };

struct Ent
{
    Vec3  pos;
    float dist;
    int   type;
};

static CRITICAL_SECTION g_snapLock;
static std::vector<Ent> g_snap;

static Vec3  g_camPos{};
static Vec3  g_camR{}, g_camU{}, g_camF{};
static bool  g_camValid = false;

static CRITICAL_SECTION g_logLock;
static std::deque<std::wstring> g_logQ;
static std::wstring g_status;

static HWND g_gui = nullptr;
static HWND g_overlay = nullptr;
static HWND g_gameWnd = nullptr;

static HHOOK g_kbHook = nullptr;
static HHOOK g_msHook = nullptr;

static std::atomic<int>  g_capture{ 0 };   // 0 none, else 1..4 = which bind is being captured
static std::atomic<bool> g_hold{ false };

static const float kDeg2Rad = 3.14159265358979f / 180.0f;

static void logf(const wchar_t* fmt, ...)
{
    wchar_t buf[1024]{};
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_logLock);
    g_logQ.push_back(buf);
    while (g_logQ.size() > 200) g_logQ.pop_front();
    LeaveCriticalSection(&g_logLock);
}

static void setStatus(const std::wstring& s)
{
    EnterCriticalSection(&g_snapLock);
    g_status = s;
    LeaveCriticalSection(&g_snapLock);
}

static bool aimActive()
{
    if (!cfg.aim) return false;
    if (!cfg.aimHoldMode) return true;
    return g_hold.load();
}

// ------------------------------------------------------------------ config io
static void configPath(wchar_t* out)
{
    GetModuleFileNameW(nullptr, out, MAX_PATH);
    wchar_t* dot = wcsrchr(out, L'.');
    if (dot) wcscpy_s(dot, MAX_PATH - static_cast<size_t>(dot - out), L".ini");
    else     wcscat_s(out, MAX_PATH, L".ini");
}

static int iniGet(const wchar_t* path, const wchar_t* key, int def)
{
    return static_cast<int>(GetPrivateProfileIntW(L"settings", key, def, path));
}

static void iniPut(const wchar_t* path, const wchar_t* key, int v)
{
    wchar_t buf[32]{};
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%d", v);
    WritePrivateProfileStringW(L"settings", key, buf, path);
}

static void saveConfig()
{
    wchar_t path[MAX_PATH]{};
    configPath(path);
    iniPut(path, L"esp", cfg.esp);
    iniPut(path, L"aim", cfg.aim);
    iniPut(path, L"instantLoot", cfg.instantLoot);
    iniPut(path, L"aimHoldMode", cfg.aimHoldMode);
    iniPut(path, L"drawBox", cfg.drawBox);
    iniPut(path, L"drawDist", cfg.drawDist);
    iniPut(path, L"drawSnapline", cfg.drawSnapline);
    iniPut(path, L"drawPlayers", cfg.drawPlayers);
    iniPut(path, L"drawContainers", cfg.drawContainers);
    iniPut(path, L"drawLoot", cfg.drawLoot);
    iniPut(path, L"drawDoors", cfg.drawDoors);
    iniPut(path, L"aimFov", cfg.aimFov);
    iniPut(path, L"smooth", cfg.smooth);
    iniPut(path, L"espFov", cfg.espFov);
    iniPut(path, L"maxDist", cfg.maxDist);
    iniPut(path, L"menuKey", cfg.menuKey);
    iniPut(path, L"espKey", cfg.espKey);
    iniPut(path, L"aimKey", cfg.aimKey);
    iniPut(path, L"holdKey", cfg.holdKey);
    iniPut(path, L"playerModelOff", cfg.playerModelOff);
    iniPut(path, L"playerListOff", cfg.playerListOff);
    iniPut(path, L"playerPosOff", cfg.playerPosOff);
    iniPut(path, L"playerHeightX10", cfg.playerHeightX10);
}

static void loadConfig()
{
    wchar_t path[MAX_PATH]{};
    configPath(path);
    cfg.esp            = iniGet(path, L"esp", cfg.esp) != 0;
    cfg.aim            = iniGet(path, L"aim", cfg.aim) != 0;
    cfg.instantLoot    = iniGet(path, L"instantLoot", cfg.instantLoot) != 0;
    cfg.aimHoldMode    = iniGet(path, L"aimHoldMode", cfg.aimHoldMode) != 0;
    cfg.drawBox        = iniGet(path, L"drawBox", cfg.drawBox) != 0;
    cfg.drawDist       = iniGet(path, L"drawDist", cfg.drawDist) != 0;
    cfg.drawSnapline   = iniGet(path, L"drawSnapline", cfg.drawSnapline) != 0;
    cfg.drawPlayers    = iniGet(path, L"drawPlayers", cfg.drawPlayers) != 0;
    cfg.drawContainers = iniGet(path, L"drawContainers", cfg.drawContainers) != 0;
    cfg.drawLoot       = iniGet(path, L"drawLoot", cfg.drawLoot) != 0;
    cfg.drawDoors      = iniGet(path, L"drawDoors", cfg.drawDoors) != 0;
    cfg.aimFov         = iniGet(path, L"aimFov", cfg.aimFov);
    cfg.smooth         = iniGet(path, L"smooth", cfg.smooth);
    cfg.espFov         = iniGet(path, L"espFov", cfg.espFov);
    cfg.maxDist        = iniGet(path, L"maxDist", cfg.maxDist);
    cfg.menuKey        = iniGet(path, L"menuKey", cfg.menuKey);
    cfg.espKey         = iniGet(path, L"espKey", cfg.espKey);
    cfg.aimKey         = iniGet(path, L"aimKey", cfg.aimKey);
    cfg.holdKey        = iniGet(path, L"holdKey", cfg.holdKey);
    cfg.playerModelOff = iniGet(path, L"playerModelOff", cfg.playerModelOff);
    cfg.playerListOff  = iniGet(path, L"playerListOff", cfg.playerListOff);
    cfg.playerPosOff   = iniGet(path, L"playerPosOff", cfg.playerPosOff);
    cfg.playerHeightX10 = iniGet(path, L"playerHeightX10", cfg.playerHeightX10);

    if (cfg.smooth < 1)   cfg.smooth = 1;
    if (cfg.smooth > 100) cfg.smooth = 100;
    if (cfg.aimFov < 10)  cfg.aimFov = 10;
    if (cfg.aimFov > 600) cfg.aimFov = 600;
    if (cfg.espFov < 30)  cfg.espFov = 30;
    if (cfg.espFov > 120) cfg.espFov = 120;
    if (cfg.maxDist < 10) cfg.maxDist = 10;
}

// ------------------------------------------------------------------ key names
static std::wstring keyName(int vk)
{
    switch (vk)
    {
    case VK_LBUTTON:  return L"LMB";
    case VK_RBUTTON:  return L"RMB";
    case VK_MBUTTON:  return L"MMB";
    case VK_XBUTTON1: return L"MB4";
    case VK_XBUTTON2: return L"MB5";
    case VK_LSHIFT:   return L"LSHIFT";
    case VK_RSHIFT:   return L"RSHIFT";
    case VK_LCONTROL: return L"LCTRL";
    case VK_RCONTROL: return L"RCTRL";
    case VK_LMENU:    return L"LALT";
    case VK_RMENU:    return L"RALT";
    case VK_SPACE:    return L"SPACE";
    case VK_TAB:      return L"TAB";
    case VK_CAPITAL:  return L"CAPS";
    case VK_INSERT:   return L"INS";
    case VK_DELETE:   return L"DEL";
    case VK_HOME:     return L"HOME";
    case VK_END:      return L"END";
    case VK_PRIOR:    return L"PGUP";
    case VK_NEXT:     return L"PGDN";
    case VK_UP:       return L"UP";
    case VK_DOWN:     return L"DOWN";
    case VK_LEFT:     return L"LEFT";
    case VK_RIGHT:    return L"RIGHT";
    case 0:           return L"NONE";
    }
    if (vk >= VK_F1 && vk <= VK_F24)
    {
        wchar_t b[8]{};
        _snwprintf_s(b, _countof(b), _TRUNCATE, L"F%d", vk - VK_F1 + 1);
        return b;
    }
    if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z'))
    {
        wchar_t b[2]{ static_cast<wchar_t>(vk), 0 };
        return b;
    }
    wchar_t b[16]{};
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"0x%02X", vk);
    return b;
}

// ------------------------------------------------------------------ game window
static HWND findGameWindow(DWORD pid)
{
    struct Ctx { DWORD pid; HWND best; long bestArea; } ctx{ pid, nullptr, 0 };

    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        DWORD p = 0;
        GetWindowThreadProcessId(h, &p);
        if (p != c->pid || !IsWindowVisible(h)) return TRUE;
        RECT rc{};
        if (!GetClientRect(h, &rc)) return TRUE;
        const long area = (rc.right - rc.left) * (rc.bottom - rc.top);
        if (area > c->bestArea) { c->bestArea = area; c->best = h; }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));

    return ctx.best;
}

// ------------------------------------------------------------------ view matrix
static std::vector<uintptr_t> g_mtxCand;
static DWORD g_lastScan = 0;
static Vec3  g_prevCam{};
static bool  g_havePrevCam = false;

static bool validateMatrixAt(uintptr_t addr, Vec3& cam, Vec3& r, Vec3& u, Vec3& f)
{
    float m[16]{};
    if (!readRaw(addr, m, sizeof(m))) return false;

    for (int i = 0; i < 16; ++i)
        if (!(m[i] == m[i]) || fabsf(m[i]) > 1e9f) return false;

    if (fabsf(m[15] - 1.0f) > 0.01f) return false;
    if (fabsf(m[3]) > 0.01f || fabsf(m[7]) > 0.01f || fabsf(m[11]) > 0.01f) return false;

    r = { m[0], m[4], m[8] };
    u = { m[1], m[5], m[9] };
    f = { m[2], m[6], m[10] };
    const Vec3 t{ m[12], m[13], m[14] };

    auto len = [](const Vec3& v) { return sqrtf(v.x * v.x + v.y * v.y + v.z * v.z); };
    auto dot = [](const Vec3& a, const Vec3& b) { return a.x * b.x + a.y * b.y + a.z * b.z; };

    const float lr = len(r), lu = len(u), lf = len(f);
    if (fabsf(lr - 1.0f) > 0.02f || fabsf(lu - 1.0f) > 0.02f || fabsf(lf - 1.0f) > 0.02f) return false;
    if (fabsf(dot(r, u)) > 0.05f || fabsf(dot(r, f)) > 0.05f || fabsf(dot(u, f)) > 0.05f) return false;

    const Vec3 cr{ u.y * f.z - u.z * f.y, u.z * f.x - u.x * f.z, u.x * f.y - u.y * f.x };
    if (fabsf(len(cr) - 1.0f) > 0.1f) return false;

    cam.x = -(t.x * r.x + t.y * u.x + t.z * f.x);
    cam.y = -(t.x * r.y + t.y * u.y + t.z * f.y);
    cam.z = -(t.x * r.z + t.y * u.z + t.z * f.z);

    if (!(cam.x == cam.x) || fabsf(cam.x) > 2e6f || fabsf(cam.y) > 2e6f || fabsf(cam.z) > 2e6f)
        return false;

    return true;
}

static void scanMatrixCandidates()
{
    g_mtxCand.clear();

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    size_t budget = 160ull * 1024 * 1024;

    std::vector<float> buf;
    while (queryRegion(addr, &mbi) && budget)
    {
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        const bool usable = mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE &&
                            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                            !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize <= 16ull * 1024 * 1024;

        if (usable && g_mtxCand.size() < 4096)
        {
            const size_t n = mbi.RegionSize / 4;
            buf.resize(n);
            if (readRaw(reinterpret_cast<uintptr_t>(mbi.BaseAddress), buf.data(), mbi.RegionSize))
            {
                budget -= (std::min)(budget, static_cast<size_t>(mbi.RegionSize));
                const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                for (size_t i = 0; i + 16 <= n; ++i)
                {
                    const float* m = buf.data() + i;
                    if (fabsf(m[15] - 1.0f) > 0.01f) continue;
                    if (fabsf(m[3]) > 0.01f || fabsf(m[7]) > 0.01f || fabsf(m[11]) > 0.01f) continue;
                    const float l0 = m[0] * m[0] + m[4] * m[4] + m[8] * m[8];
                    if (l0 < 0.96f || l0 > 1.04f) continue;
                    g_mtxCand.push_back(base + i * 4);
                    if (g_mtxCand.size() >= 4096) break;
                }
            }
        }

        if (next <= addr) break;
        addr = next;
    }

    g_lastScan = GetTickCount();
    logf(L"matrix scan: %zu candidates", g_mtxCand.size());
}

static int scoreCandidate(uintptr_t addr, Vec3* outCam, Vec3* outR, Vec3* outU, Vec3* outF)
{
    Vec3 cam{}, r{}, u{}, f{};
    if (!validateMatrixAt(addr, cam, r, u, f)) return -1;

    EnterCriticalSection(&g_snapLock);
    std::vector<Ent> local = g_snap;
    LeaveCriticalSection(&g_snapLock);

    int score = 0;
    const int n = (std::min)(static_cast<int>(local.size()), 24);

    for (int i = 0; i < n; ++i)
    {
        const Vec3& p = local[i].pos;
        const Vec3 d{ p.x - cam.x, p.y - cam.y, p.z - cam.z };
        const float z = -(d.x * f.x + d.y * f.y + d.z * f.z);
        if (z < 0.2f || z > 400.f) continue;

        const float x = d.x * r.x + d.y * r.y + d.z * r.z;
        const float y = d.x * u.x + d.y * u.y + d.z * u.z;
        const float fx = 1.0f / tanf(30.0f * kDeg2Rad);
        const float nx = (x / z) * fx;
        const float ny = (y / z) * fx;
        if (fabsf(nx) < 1.6f && fabsf(ny) < 1.6f) score += 10;
        else score += 1;
    }

    if (g_havePrevCam)
    {
        const float dx = cam.x - g_prevCam.x, dy = cam.y - g_prevCam.y, dz = cam.z - g_prevCam.z;
        const float moved = sqrtf(dx * dx + dy * dy + dz * dz);
        if (moved > 40.0f) score -= 25;
        else if (moved > 8.0f) score -= 6;
    }

    if (outCam) *outCam = cam;
    if (outR) *outR = r;
    if (outU) *outU = u;
    if (outF) *outF = f;
    return score;
}

static void updateCamera()
{
    const DWORD now = GetTickCount();

    bool needScan = g_mtxCand.empty() || (now - g_lastScan) > 4000;
    if (needScan) scanMatrixCandidates();

    int bestScore = -1000;
    uintptr_t bestAddr = 0;
    Vec3 bestCam{}, bestR{}, bestU{}, bestF{};

    for (uintptr_t a : g_mtxCand)
    {
        Vec3 cam{}, r{}, u{}, f{};
        const int s = scoreCandidate(a, &cam, &r, &u, &f);
        if (s > bestScore) { bestScore = s; bestAddr = a; bestCam = cam; bestR = r; bestU = u; bestF = f; }
        if (bestScore > 24 * 10) break;
    }

    if (bestAddr && bestScore > 0)
    {
        g_camPos = bestCam;
        g_camR = bestR; g_camU = bestU; g_camF = bestF;
        g_camValid = true;
        g_prevCam = bestCam;
        g_havePrevCam = true;
    }
    else if (!bestAddr)
    {
        g_camValid = false;
        g_mtxCand.clear();
    }
}

static bool w2s(const Vec3& p, float w, float h, float fovDeg, float* sx, float* sy, float* zOut)
{
    if (!g_camValid) return false;

    const Vec3 d{ p.x - g_camPos.x, p.y - g_camPos.y, p.z - g_camPos.z };
    const float z = -(d.x * g_camF.x + d.y * g_camF.y + d.z * g_camF.z);
    if (z < 0.15f) return false;

    const float x = d.x * g_camR.x + d.y * g_camR.y + d.z * g_camR.z;
    const float y = d.x * g_camU.x + d.y * g_camU.y + d.z * g_camU.z;

    const float focal = 1.0f / tanf(fovDeg * 0.5f * kDeg2Rad);
    const float aspect = (h > 0.0f) ? (w / h) : 1.0f;

    const float nx = (x / z) * focal / aspect;
    const float ny = (y / z) * focal;

    *sx = (nx * 0.5f + 0.5f) * w;
    *sy = (0.5f - ny * 0.5f) * h;
    if (zOut) *zOut = z;
    return true;
}

// ------------------------------------------------------------------ entities
static void collectList(uintptr_t model, int listOff, int posOff, int type,
                        std::vector<Ent>& out, const Vec3& cam)
{
    uintptr_t list = 0;
    if (!readPtr(model + listOff, &list) || list < 0x10000) return;

    uintptr_t items = 0;
    if (!readPtr(list + 0x10, &items) || items < 0x10000) return;

    const int size = read<int>(list + 0x18);
    if (size <= 0 || size > 4096) return;

    int stride = 0x18;
    int entOff = 0x10;
    {
        uintptr_t probe = 0;
        if (!readPtr(items + 0x20 + entOff, &probe) || probe < 0x10000)
        {
            stride = static_cast<int>(g_ptrSize);
            entOff = 0;
        }
    }

    const int cap = (std::min)(size, 400);
    for (int i = 0; i < cap; ++i)
    {
        uintptr_t ent = 0;
        if (!readPtr(items + 0x20 + static_cast<uintptr_t>(i) * stride + entOff, &ent) || ent < 0x10000)
            continue;

        uintptr_t pos = 0;
        if (!readPtr(ent + posOff, &pos) || pos < 0x10000) continue;

        Vec3 p{ read<float>(pos + 0x10), read<float>(pos + 0x14), read<float>(pos + 0x18) };
        if (!(p.x == p.x) || !(p.y == p.y) || !(p.z == p.z)) continue;
        if (fabsf(p.x) > 200000.f || fabsf(p.y) > 200000.f || fabsf(p.z) > 200000.f) continue;

        const float dx = p.x - cam.x, dy = p.y - cam.y, dz = p.z - cam.z;
        const float dist = sqrtf(dx * dx + dy * dy + dz * dz);
        if (dist > static_cast<float>(cfg.maxDist)) continue;
        if (type == T_PLAYER && dist < 0.6f) continue;

        out.push_back({ p, dist, type });
    }
}

static void snapshotEntities(uintptr_t bu)
{
    std::vector<Ent> out;
    const Vec3 cam = g_camPos;

    if (cfg.drawPlayers)
    {
        uintptr_t model = 0;
        if (readPtr(bu + static_cast<uintptr_t>(cfg.playerModelOff), &model) && model > 0x10000)
            collectList(model, cfg.playerListOff, cfg.playerPosOff, T_PLAYER, out, cam);
    }

    uintptr_t ents = 0;
    if (readPtr(bu + 0x18, &ents) && ents > 0x10000)
    {
        uintptr_t world = 0;
        if (readPtr(ents + 0x60, &world) && world > 0x10000)
        {
            if (cfg.drawContainers) collectList(world, 0x20, 0x28, T_CONTAINER, out, cam);
            if (cfg.drawLoot)     { collectList(world, 0x38, 0x28, T_LOOT, out, cam);
                                    collectList(world, 0x40, 0x28, T_VEHICLE, out, cam); }
            if (cfg.drawDoors)    collectList(world, 0x48, 0x38, T_DOOR, out, cam);
        }
    }

    std::sort(out.begin(), out.end(), [](const Ent& a, const Ent& b) { return a.dist < b.dist; });
    if (out.size() > 300) out.resize(300);

    EnterCriticalSection(&g_snapLock);
    g_snap.swap(out);
    LeaveCriticalSection(&g_snapLock);
}

// ------------------------------------------------------------------ aim
static void doAim()
{
    if (!g_camValid || !g_gameWnd) return;
    if (GetForegroundWindow() != g_gameWnd) return;

    RECT rc{};
    if (!GetClientRect(g_gameWnd, &rc)) return;
    const float w = static_cast<float>(rc.right - rc.left);
    const float h = static_cast<float>(rc.bottom - rc.top);
    if (w < 32 || h < 32) return;

    const float cx = w * 0.5f, cy = h * 0.5f;

    EnterCriticalSection(&g_snapLock);
    std::vector<Ent> local = g_snap;
    LeaveCriticalSection(&g_snapLock);

    float bestDelta = 1e9f;
    float bestX = 0, bestY = 0;
    bool found = false;

    const float fov = static_cast<float>(cfg.aimFov);

    for (const Ent& e : local)
    {
        if (e.type != T_PLAYER) continue;

        Vec3 head = e.pos;
        head.y += cfg.playerHeightX10 * 0.1f;

        float sx = 0, sy = 0;
        if (!w2s(head, w, h, static_cast<float>(cfg.espFov), &sx, &sy, nullptr)) continue;

        const float dx = sx - cx, dy = sy - cy;
        const float d = sqrtf(dx * dx + dy * dy);
        if (d > fov) continue;
        if (d < bestDelta) { bestDelta = d; bestX = dx; bestY = dy; found = true; }
    }

    if (!found || bestDelta < 1.5f) return;

    const float factor = static_cast<float>(cfg.smooth) / 100.0f;
    int mx = static_cast<int>(bestX * factor);
    int my = static_cast<int>(bestY * factor);
    if (mx == 0 && my == 0) return;

    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dx = mx;
    in.mi.dy = my;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &in, sizeof(in));
}

// ------------------------------------------------------------------ overlay
static void positionOverlay()
{
    if (!g_overlay) return;

    if (!cfg.esp || !g_gameWnd || !IsWindow(g_gameWnd) || GetForegroundWindow() != g_gameWnd)
    {
        ShowWindow(g_overlay, SW_HIDE);
        return;
    }

    RECT rc{};
    POINT tl{ 0, 0 };
    if (!GetClientRect(g_gameWnd, &rc)) { ShowWindow(g_overlay, SW_HIDE); return; }
    ClientToScreen(g_gameWnd, &tl);

    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) { ShowWindow(g_overlay, SW_HIDE); return; }

    SetWindowPos(g_overlay, HWND_TOPMOST, tl.x, tl.y, w, h,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

static void drawEsp(HDC mem, int w, int h)
{
    EnterCriticalSection(&g_snapLock);
    std::vector<Ent> local = g_snap;
    const bool camOk = g_camValid;
    LeaveCriticalSection(&g_snapLock);

    if (!camOk) return;

    HPEN penBox   = CreatePen(PS_SOLID, 1, RGB(235, 70, 70));
    HPEN penLoot  = CreatePen(PS_SOLID, 1, RGB(90, 220, 90));
    HPEN penCont  = CreatePen(PS_SOLID, 1, RGB(240, 200, 60));
    HPEN penDoor  = CreatePen(PS_SOLID, 1, RGB(80, 200, 240));
    HPEN penVeh   = CreatePen(PS_SOLID, 1, RGB(200, 120, 240));
    HPEN penSnap  = CreatePen(PS_SOLID, 1, RGB(160, 160, 160));
    HGDIOBJ oldPen = SelectObject(mem, penBox);

    HFONT font = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HGDIOBJ oldFont = SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    const float fw = static_cast<float>(w);
    const float fh = static_cast<float>(h);
    const float fov = static_cast<float>(cfg.espFov);

    for (const Ent& e : local)
    {
        const float height = (e.type == T_PLAYER) ? (cfg.playerHeightX10 * 0.1f)
                           : (e.type == T_DOOR)   ? 1.9f
                           : 0.5f;

        Vec3 head = e.pos;
        head.y += height;

        float x1 = 0, y1 = 0, x2 = 0, y2 = 0;
        if (!w2s(e.pos, fw, fh, fov, &x1, &y1, nullptr)) continue;
        if (!w2s(head, fw, fh, fov, &x2, &y2, nullptr)) continue;

        float boxH = y1 - y2;
        if (boxH < 3.0f) boxH = 3.0f;
        if (boxH > fh) boxH = fh;

        const float boxW = boxH * 0.45f;
        const int left   = static_cast<int>(x1 - boxW * 0.5f);
        const int top    = static_cast<int>(y2);
        const int right  = static_cast<int>(x1 + boxW * 0.5f);
        const int bottom = static_cast<int>(y2 + boxH);

        if (right < 0 || left > w || bottom < 0 || top > h) continue;

        COLORREF col = RGB(235, 70, 70);
        HPEN usePen = penBox;
        switch (e.type)
        {
        case T_CONTAINER: col = RGB(240, 200, 60); usePen = penCont; break;
        case T_LOOT:      col = RGB(90, 220, 90);  usePen = penLoot; break;
        case T_VEHICLE:   col = RGB(200, 120, 240); usePen = penVeh; break;
        case T_DOOR:      col = RGB(80, 200, 240); usePen = penDoor; break;
        }

        if (cfg.drawBox)
        {
            SelectObject(mem, usePen);
            HGDIOBJ oldBr = SelectObject(mem, GetStockObject(NULL_BRUSH));
            Rectangle(mem, left, top, right, bottom);
            SelectObject(mem, oldBr);
        }

        if (cfg.drawSnapline)
        {
            SelectObject(mem, penSnap);
            MoveToEx(mem, static_cast<int>(fw * 0.5f), h - 1, nullptr);
            LineTo(mem, static_cast<int>(x1), bottom);
        }

        if (cfg.drawDist)
        {
            wchar_t label[32]{};
            _snwprintf_s(label, _countof(label), _TRUNCATE, L"%dm", static_cast<int>(e.dist + 0.5f));
            SetTextColor(mem, col);
            TextOutW(mem, left, top - 15, label, static_cast<int>(wcslen(label)));
        }
    }

    if (cfg.aim && aimActive() && cfg.aimHoldMode)
    {
        HPEN fovPen = CreatePen(PS_DOT, 1, RGB(120, 255, 120));
        SelectObject(mem, fovPen);
        HGDIOBJ oldBr = SelectObject(mem, GetStockObject(NULL_BRUSH));
        Ellipse(mem, static_cast<int>(fw * 0.5f - cfg.aimFov), static_cast<int>(fh * 0.5f - cfg.aimFov),
                     static_cast<int>(fw * 0.5f + cfg.aimFov), static_cast<int>(fh * 0.5f + cfg.aimFov));
        SelectObject(mem, oldBr);
        DeleteObject(fovPen);
    }

    SelectObject(mem, oldFont);
    SelectObject(mem, oldPen);
    DeleteObject(font);
    DeleteObject(penBox); DeleteObject(penLoot); DeleteObject(penCont);
    DeleteObject(penDoor); DeleteObject(penVeh); DeleteObject(penSnap);
}

static void renderOverlay()
{
    if (!g_overlay || !IsWindowVisible(g_overlay)) return;

    RECT rc{};
    if (!GetClientRect(g_overlay, &rc)) return;
    const int w = rc.right, h = rc.bottom;
    if (w <= 0 || h <= 0) return;

    HDC hdc = GetDC(g_overlay);
    if (!hdc) return;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);

    HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    drawEsp(mem, w, h);

    BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);

    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(g_overlay, hdc);
}

static LRESULT CALLBACK OverlayProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_TIMER:
        positionOverlay();
        renderOverlay();
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        BeginPaint(h, &ps);
        EndPaint(h, &ps);
        renderOverlay();
        return 0;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static void createOverlay()
{
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = OverlayProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"ilOverlayWnd";
    RegisterClassExW(&wc);

    g_overlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        L"ilOverlayWnd", L"", WS_POPUP, 0, 0, 64, 64,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (g_overlay)
    {
        SetLayeredWindowAttributes(g_overlay, RGB(0, 0, 0), 0, LWA_COLORKEY);
        SetTimer(g_overlay, 1, 16, nullptr);
    }
}

// ------------------------------------------------------------------ gui
#define WM_APP_TOGGLE   (WM_APP + 1)
#define WM_APP_ESP      (WM_APP + 2)
#define WM_APP_AIM      (WM_APP + 3)
#define WM_APP_CAPTURED (WM_APP + 4)

#define IDC_ESP        1001
#define IDC_AIM        1002
#define IDC_LOOT       1003
#define IDC_BOX        1004
#define IDC_DIST       1005
#define IDC_SNAP       1006
#define IDC_PLAYERS    1007
#define IDC_CONTAINERS 1008
#define IDC_LOOTENTS   1009
#define IDC_DOORS      1010
#define IDC_AFOV       1011
#define IDC_SMOOTH     1012
#define IDC_EFOV       1013
#define IDC_MAXDIST    1014
#define IDC_KMENU      1015
#define IDC_KESP       1016
#define IDC_KAIM       1017
#define IDC_KHOLD      1018
#define IDC_PMOFF      1019
#define IDC_PLOFF      1020
#define IDC_PPOFF      1021
#define IDC_PROBE      1022
#define IDC_SAVE       1023
#define IDC_STATUS     1024
#define IDC_LOG        1025
#define IDC_TMODE      1026

static HWND g_hStatus = nullptr;
static HWND g_hLog = nullptr;

static void setCheck(HWND parent, int id, bool v)
{
    if (HWND h = GetDlgItem(parent, id)) SendMessageW(h, BM_SETCHECK, v ? BST_CHECKED : BST_UNCHECKED, 0);
}

static void syncControls(HWND h)
{
    setCheck(h, IDC_ESP, cfg.esp);
    setCheck(h, IDC_AIM, cfg.aim);
    setCheck(h, IDC_LOOT, cfg.instantLoot);
    setCheck(h, IDC_BOX, cfg.drawBox);
    setCheck(h, IDC_DIST, cfg.drawDist);
    setCheck(h, IDC_SNAP, cfg.drawSnapline);
    setCheck(h, IDC_PLAYERS, cfg.drawPlayers);
    setCheck(h, IDC_CONTAINERS, cfg.drawContainers);
    setCheck(h, IDC_LOOTENTS, cfg.drawLoot);
    setCheck(h, IDC_DOORS, cfg.drawDoors);
    setCheck(h, IDC_TMODE, cfg.aimHoldMode);

    SendDlgItemMessageW(h, IDC_AFOV, TBM_SETPOS, TRUE, cfg.aimFov);
    SendDlgItemMessageW(h, IDC_SMOOTH, TBM_SETPOS, TRUE, cfg.smooth);
    SendDlgItemMessageW(h, IDC_EFOV, TBM_SETPOS, TRUE, cfg.espFov);
    SendDlgItemMessageW(h, IDC_MAXDIST, TBM_SETPOS, TRUE, cfg.maxDist);

    wchar_t b[64]{};
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"Menu key: %s", keyName(cfg.menuKey).c_str());
    SetDlgItemTextW(h, IDC_KMENU, b);
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"ESP key: %s", keyName(cfg.espKey).c_str());
    SetDlgItemTextW(h, IDC_KESP, b);
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"Aimbot key: %s", keyName(cfg.aimKey).c_str());
    SetDlgItemTextW(h, IDC_KAIM, b);
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"Aim hold key: %s", keyName(cfg.holdKey).c_str());
    SetDlgItemTextW(h, IDC_KHOLD, b);

    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%X", cfg.playerModelOff);
    SetDlgItemTextW(h, IDC_PMOFF, b);
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%X", cfg.playerListOff);
    SetDlgItemTextW(h, IDC_PLOFF, b);
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%X", cfg.playerPosOff);
    SetDlgItemTextW(h, IDC_PPOFF, b);
}

static void readOffsetBoxes(HWND h)
{
    wchar_t b[32]{};
    GetDlgItemTextW(h, IDC_PMOFF, b, 31); if (b[0]) cfg.playerModelOff = static_cast<int>(wcstoul(b, nullptr, 16));
    GetDlgItemTextW(h, IDC_PLOFF, b, 31); if (b[0]) cfg.playerListOff  = static_cast<int>(wcstoul(b, nullptr, 16));
    GetDlgItemTextW(h, IDC_PPOFF, b, 31); if (b[0]) cfg.playerPosOff   = static_cast<int>(wcstoul(b, nullptr, 16));
}

static void probeModel(uintptr_t model, const wchar_t* name)
{
    if (!model) { logf(L"probe %s: null model", name); return; }

    for (int off = 0; off < 0x400; off += 8)
    {
        uintptr_t list = 0;
        if (!readPtr(model + off, &list) || list < 0x10000) continue;

        uintptr_t items = 0;
        if (!readPtr(list + 0x10, &items) || items < 0x10000) continue;

        const int size = read<int>(list + 0x18);
        if (size <= 0 || size > 3000) continue;

        uintptr_t e0 = 0;
        if (!readPtr(items + 0x20 + 0x10, &e0) || e0 < 0x10000) continue;

        uintptr_t pos = 0;
        if (!readPtr(e0 + 0x28, &pos) || pos < 0x10000) continue;

        const Vec3 p{ read<float>(pos + 0x10), read<float>(pos + 0x14), read<float>(pos + 0x18) };
        if (!(p.x == p.x) || fabsf(p.x) > 200000.f) continue;

        logf(L"%s+0x%X -> %d entries, first %.1f %.1f %.1f", name, off, size, p.x, p.y, p.z);
        Sleep(3);
    }
}

static void runProbe()
{
    std::thread([]{
        const uintptr_t bu = g_bu.load();
        if (!bu) { logf(L"probe: battleUpdater not resolved yet"); return; }

        logf(L"--- probe start ---");

        uintptr_t ents = 0;
        if (readPtr(bu + 0x18, &ents) && ents > 0x10000)
        {
            probeModel(ents, L"battle");
            uintptr_t world = 0;
            if (readPtr(ents + 0x60, &world) && world > 0x10000) probeModel(world, L"world");
        }
        else logf(L"probe: no battleEntitiesModel");

        logf(L"--- probe done ---");
    }).detach();
}

static LRESULT CALLBACK GuiProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HINSTANCE inst = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(h, GWLP_HINSTANCE));
        HFONT f = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style,
                      int x, int y, int w, int hh, int id) -> HWND
        {
            HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                                     x, y, w, hh, h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                     inst, nullptr);
            if (c && f) SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
            return c;
        };

        int y = 8;
        mk(L"BUTTON", L"ESP  [toggle]", BS_AUTOCHECKBOX, 10, y, 170, 22, IDC_ESP);
        mk(L"BUTTON", L"Aimbot  [toggle]", BS_AUTOCHECKBOX, 190, y, 170, 22, IDC_AIM); y += 26;
        mk(L"BUTTON", L"Instant loot", BS_AUTOCHECKBOX, 10, y, 170, 22, IDC_LOOT);
        mk(L"BUTTON", L"Aim: hold key", BS_AUTOCHECKBOX, 190, y, 170, 22, IDC_TMODE); y += 26;

        mk(L"STATIC", L"ESP elements", 0, 10, y, 200, 18, -1); y += 20;
        mk(L"BUTTON", L"Boxes", BS_AUTOCHECKBOX, 10, y, 85, 22, IDC_BOX);
        mk(L"BUTTON", L"Distance", BS_AUTOCHECKBOX, 100, y, 85, 22, IDC_DIST);
        mk(L"BUTTON", L"Snaplines", BS_AUTOCHECKBOX, 190, y, 95, 22, IDC_SNAP); y += 24;
        mk(L"BUTTON", L"Players", BS_AUTOCHECKBOX, 10, y, 85, 22, IDC_PLAYERS);
        mk(L"BUTTON", L"Containers", BS_AUTOCHECKBOX, 100, y, 95, 22, IDC_CONTAINERS);
        mk(L"BUTTON", L"Doors", BS_AUTOCHECKBOX, 200, y, 80, 22, IDC_DOORS); y += 24;
        mk(L"BUTTON", L"Loot", BS_AUTOCHECKBOX, 10, y, 85, 22, IDC_LOOTENTS); y += 28;

        mk(L"STATIC", L"Aim FOV (px)", 0, 10, y, 180, 18, -1);
        mk(L"STATIC", L"Smoothing", 0, 200, y, 160, 18, -1); y += 18;
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 10, y, 180, 24, IDC_AFOV);
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 200, y, 170, 24, IDC_SMOOTH); y += 30;
        SendDlgItemMessageW(h, IDC_AFOV, TBM_SETRANGE, TRUE, MAKELPARAM(10, 600));
        SendDlgItemMessageW(h, IDC_SMOOTH, TBM_SETRANGE, TRUE, MAKELPARAM(1, 100));

        mk(L"STATIC", L"ESP FOV (projection)", 0, 10, y, 180, 18, -1);
        mk(L"STATIC", L"Max distance", 0, 200, y, 160, 18, -1); y += 18;
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 10, y, 180, 24, IDC_EFOV);
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 200, y, 170, 24, IDC_MAXDIST); y += 30;
        SendDlgItemMessageW(h, IDC_EFOV, TBM_SETRANGE, TRUE, MAKELPARAM(30, 120));
        SendDlgItemMessageW(h, IDC_MAXDIST, TBM_SETRANGE, TRUE, MAKELPARAM(10, 500));

        mk(L"STATIC", L"Keybinds", 0, 10, y, 200, 18, -1); y += 20;
        mk(L"BUTTON", L"Menu key", BS_PUSHBUTTON, 10, y, 110, 24, IDC_KMENU);
        mk(L"BUTTON", L"ESP key", BS_PUSHBUTTON, 130, y, 110, 24, IDC_KESP);
        mk(L"BUTTON", L"Aimbot key", BS_PUSHBUTTON, 250, y, 120, 24, IDC_KAIM); y += 28;
        mk(L"BUTTON", L"Aim hold key", BS_PUSHBUTTON, 10, y, 110, 24, IDC_KHOLD); y += 32;

        mk(L"STATIC", L"Player model / list / pos (hex)", 0, 10, y, 300, 18, -1); y += 20;
        mk(L"EDIT", L"", WS_BORDER | ES_UPPERCASE, 10, y, 80, 22, IDC_PMOFF);
        mk(L"EDIT", L"", WS_BORDER | ES_UPPERCASE, 100, y, 80, 22, IDC_PLOFF);
        mk(L"EDIT", L"", WS_BORDER | ES_UPPERCASE, 190, y, 80, 22, IDC_PPOFF);
        mk(L"BUTTON", L"Probe", BS_PUSHBUTTON, 280, y, 90, 22, IDC_PROBE); y += 28;

        mk(L"BUTTON", L"Save config", BS_PUSHBUTTON, 10, y, 120, 26, IDC_SAVE); y += 32;

        g_hStatus = mk(L"STATIC", L"starting...", 0, 10, y, 360, 34, IDC_STATUS); y += 38;
        g_hLog = mk(L"LISTBOX", L"", WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                    10, y, 360, 120, IDC_LOG);

        syncControls(h);
        return 0;
    }

    case WM_HSCROLL:
    {
        HWND src = reinterpret_cast<HWND>(lp);
        const int id = GetDlgCtrlID(src);
        const int pos = static_cast<int>(SendMessageW(src, TBM_GETPOS, 0, 0));
        if (id == IDC_AFOV)   cfg.aimFov = pos;
        if (id == IDC_SMOOTH) cfg.smooth = pos;
        if (id == IDC_EFOV)   cfg.espFov = pos;
        if (id == IDC_MAXDIST) cfg.maxDist = pos;
        return 0;
    }

    case WM_COMMAND:
    {
        const int id = LOWORD(wp);
        const int code = HIWORD(wp);

        if (code == BN_CLICKED)
        {
            switch (id)
            {
            case IDC_ESP:   cfg.esp = IsDlgButtonChecked(h, IDC_ESP) == BST_CHECKED; return 0;
            case IDC_AIM:   cfg.aim = IsDlgButtonChecked(h, IDC_AIM) == BST_CHECKED; return 0;
            case IDC_LOOT:  cfg.instantLoot = IsDlgButtonChecked(h, IDC_LOOT) == BST_CHECKED; return 0;
            case IDC_BOX:   cfg.drawBox = IsDlgButtonChecked(h, IDC_BOX) == BST_CHECKED; return 0;
            case IDC_DIST:  cfg.drawDist = IsDlgButtonChecked(h, IDC_DIST) == BST_CHECKED; return 0;
            case IDC_SNAP:  cfg.drawSnapline = IsDlgButtonChecked(h, IDC_SNAP) == BST_CHECKED; return 0;
            case IDC_PLAYERS: cfg.drawPlayers = IsDlgButtonChecked(h, IDC_PLAYERS) == BST_CHECKED; return 0;
            case IDC_CONTAINERS: cfg.drawContainers = IsDlgButtonChecked(h, IDC_CONTAINERS) == BST_CHECKED; return 0;
            case IDC_LOOTENTS: cfg.drawLoot = IsDlgButtonChecked(h, IDC_LOOTENTS) == BST_CHECKED; return 0;
            case IDC_DOORS: cfg.drawDoors = IsDlgButtonChecked(h, IDC_DOORS) == BST_CHECKED; return 0;
            case IDC_TMODE:
                cfg.aimHoldMode = IsDlgButtonChecked(h, IDC_TMODE) == BST_CHECKED;
                if (!cfg.aimHoldMode) g_hold = true;
                return 0;

            case IDC_KMENU: g_capture = 1; SetDlgItemTextW(h, IDC_KMENU, L"Menu key: ..."); return 0;
            case IDC_KESP:  g_capture = 2; SetDlgItemTextW(h, IDC_KESP, L"ESP key: ..."); return 0;
            case IDC_KAIM:  g_capture = 3; SetDlgItemTextW(h, IDC_KAIM, L"Aimbot key: ..."); return 0;
            case IDC_KHOLD: g_capture = 4; SetDlgItemTextW(h, IDC_KHOLD, L"Aim hold key: ..."); return 0;

            case IDC_PROBE:
                readOffsetBoxes(h);
                runProbe();
                return 0;

            case IDC_SAVE:
                readOffsetBoxes(h);
                saveConfig();
                logf(L"config saved");
                return 0;
            }
        }
        return 0;
    }

    case WM_APP_CAPTURED:
    {
        const int vk = static_cast<int>(wp);
        const int which = g_capture.exchange(0);
        if (vk == VK_ESCAPE) { syncControls(h); return 0; }

        if (which == 1) cfg.menuKey = vk;
        if (which == 2) cfg.espKey = vk;
        if (which == 3) cfg.aimKey = vk;
        if (which == 4) cfg.holdKey = vk;

        logf(L"bind set: %s", keyName(vk).c_str());
        syncControls(h);
        return 0;
    }

    case WM_APP_TOGGLE:
        if (IsWindowVisible(h))
        {
            if (GetForegroundWindow() == h) ShowWindow(h, SW_HIDE);
            else SetForegroundWindow(h);
        }
        else
        {
            ShowWindow(h, SW_SHOW);
            SetForegroundWindow(h);
        }
        return 0;

    case WM_APP_ESP:
        cfg.esp = !cfg.esp;
        syncControls(h);
        return 0;

    case WM_APP_AIM:
        cfg.aim = !cfg.aim;
        syncControls(h);
        return 0;

    case WM_TIMER:
    {
        std::wstring st;
        EnterCriticalSection(&g_snapLock);
        st = g_status;
        LeaveCriticalSection(&g_snapLock);
        if (g_hStatus) SetWindowTextW(g_hStatus, st.c_str());

        EnterCriticalSection(&g_logLock);
        while (!g_logQ.empty())
        {
            std::wstring line = g_logQ.front();
            g_logQ.pop_front();
            LeaveCriticalSection(&g_logLock);
            if (g_hLog)
            {
                const int idx = static_cast<int>(SendMessageW(g_hLog, LB_ADDSTRING, 0,
                                                              reinterpret_cast<LPARAM>(line.c_str())));
                SendMessageW(g_hLog, LB_SETTOPINDEX, static_cast<WPARAM>(idx), 0);
            }
            EnterCriticalSection(&g_logLock);
        }
        LeaveCriticalSection(&g_logLock);
        return 0;
    }

    case WM_CLOSE:
        ShowWindow(h, SW_HIDE);
        return 0;
    }

    return DefWindowProcW(h, msg, wp, lp);
}

static void createGui()
{
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = GuiProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ilGuiWnd";
    RegisterClassExW(&wc);

    g_gui = CreateWindowExW(WS_EX_TOPMOST, L"ilGuiWnd", L"instant loot",
                            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                            CW_USEDEFAULT, CW_USEDEFAULT, 400, 700,
                            nullptr, nullptr, wc.hInstance, nullptr);

    if (g_gui) SetTimer(g_gui, 2, 400, nullptr);
}

// ------------------------------------------------------------------ hooks
static bool gameFocused()
{
    const HWND fg = GetForegroundWindow();
    if (!fg) return false;
    if (fg == g_gameWnd) return true;
    if (g_gui && (fg == g_gui || IsChild(g_gui, fg))) return true;
    return false;
}

static void captureKey(int vk)
{
    if (g_capture.load() && g_gui)
        PostMessageW(g_gui, WM_APP_CAPTURED, static_cast<WPARAM>(vk), 0);
}

static LRESULT CALLBACK LLKeyboard(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION)
    {
        const auto* k = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        const bool down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        const DWORD vk = k->vkCode;

        if (g_capture.load())
        {
            if (down) captureKey(static_cast<int>(vk));
            return 1;
        }

        const bool mine = gameFocused();

        if (static_cast<int>(vk) == cfg.holdKey)
            g_hold = down;

        if (mine && down)
        {
            if (static_cast<int>(vk) == cfg.menuKey)
            {
                PostMessageW(g_gui, WM_APP_TOGGLE, 0, 0);
                return 1;
            }
            if (static_cast<int>(vk) == cfg.espKey)
            {
                PostMessageW(g_gui, WM_APP_ESP, 0, 0);
                return 1;
            }
            if (static_cast<int>(vk) == cfg.aimKey)
            {
                PostMessageW(g_gui, WM_APP_AIM, 0, 0);
                return 1;
            }
        }
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

static LRESULT CALLBACK LLMouse(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION)
    {
        const auto* m = reinterpret_cast<MSLLHOOKSTRUCT*>(lp);
        int vk = 0;
        bool down = false;

        switch (wp)
        {
        case WM_LBUTTONDOWN: down = true; vk = VK_LBUTTON; break;
        case WM_LBUTTONUP:   vk = VK_LBUTTON; break;
        case WM_RBUTTONDOWN: down = true; vk = VK_RBUTTON; break;
        case WM_RBUTTONUP:   vk = VK_RBUTTON; break;
        case WM_MBUTTONDOWN: down = true; vk = VK_MBUTTON; break;
        case WM_MBUTTONUP:   vk = VK_MBUTTON; break;
        case WM_XBUTTONDOWN:
            down = true;
            vk = (HIWORD(m->mouseData) == XBUTTON2) ? VK_XBUTTON2 : VK_XBUTTON1;
            break;
        case WM_XBUTTONUP:
            vk = (HIWORD(m->mouseData) == XBUTTON2) ? VK_XBUTTON2 : VK_XBUTTON1;
            break;
        }

        if (!vk) return CallNextHookEx(nullptr, code, wp, lp);

        if (g_capture.load())
        {
            if (down) captureKey(vk);
            return CallNextHookEx(nullptr, code, wp, lp);
        }

        if (vk == cfg.holdKey) g_hold = down;

        if (down && gameFocused() && vk == cfg.aimKey)
            PostMessageW(g_gui, WM_APP_AIM, 0, 0);
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

static void installHooks()
{
    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, LLKeyboard, GetModuleHandleW(nullptr), 0);
    g_msHook = SetWindowsHookExW(WH_MOUSE_LL, LLMouse, GetModuleHandleW(nullptr), 0);
}

// ------------------------------------------------------------------ worker
static void workerThread()
{
    int misses = 0;

    while (g_running.load())
    {
        if (!g_proc)
        {
            Sleep(200);
            continue;
        }

        uintptr_t bu = g_bu.load();
        bool buOk = false;
        if (bu)
        {
            uintptr_t content = 0;
            buOk = readPtr(bu + 0x68, &content) && content > 0x10000;
        }
        if (!buOk)
        {
            bu = findBattleUpdater(false);
            g_bu = bu;
        }

        if (!bu)
        {
            if (++misses > 10)
            {
                logf(L"battleUpdater not found");
                misses = 0;
            }
            setStatus(L"battleUpdater: not found");
            Sleep(250);
            continue;
        }
        misses = 0;

        if (cfg.instantLoot) InstantLoot(bu);

        updateCamera();

        const bool needEnts = cfg.esp || (cfg.aim && aimActive());
        if (needEnts) snapshotEntities(bu);
        else
        {
            EnterCriticalSection(&g_snapLock);
            g_snap.clear();
            LeaveCriticalSection(&g_snapLock);
        }

        if (cfg.aim && aimActive()) doAim();

        EnterCriticalSection(&g_snapLock);
        const size_t n = g_snap.size();
        const bool cam = g_camValid;
        LeaveCriticalSection(&g_snapLock);

        wchar_t st[256]{};
        _snwprintf_s(st, _countof(st), _TRUNCATE,
                     L"base %p  bu %p\nentities %zu  cam %s  esp %s  aim %s",
                     (void*)g_base, (void*)bu, n, cam ? L"ok" : L"scanning",
                     cfg.esp ? L"on" : L"off", aimActive() ? L"on" : L"off");
        setStatus(st);

        Sleep(cfg.esp || cfg.aim ? 12 : 60);
    }
}

// ------------------------------------------------------------------ main
int main(int argc, char** argv)
{
    SetConsoleTitleW(L"instant loot");
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    InitializeCriticalSection(&g_snapLock);
    InitializeCriticalSection(&g_logLock);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    loadConfig();

    if (!isElevated())
    {
        printf("[!] not elevated - requesting UAC\n");
        if (relaunchElevated()) return 0;
        printf("[!] relaunch failed (%lu), continuing unelevated\n", GetLastError());
    }
    if (!enableDebugPrivilege())
        printf("[!] SeDebugPrivilege not enabled (%lu)\n", GetLastError());

    bool watch = false, loot = false, doDiag = false, guiMode = true;
    wchar_t nameArg[MAX_PATH] = L"";
    DWORD pidArg = 0;

    for (int i = 1; i < argc; ++i)
    {
        if (!_stricmp(argv[i], "--watch")) { watch = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--loot"))  { loot = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--diag"))  { doDiag = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--gui"))   { guiMode = true; continue; }
        if (!_stricmp(argv[i], "--list"))  { printList(); system("pause"); return 0; }
        if (!_stricmp(argv[i], "--pid") && i + 1 < argc)
        {
            pidArg = static_cast<DWORD>(strtoul(argv[++i], nullptr, 10));
            continue;
        }
        if (!_stricmp(argv[i], "--base") && i + 1 < argc)
        {
            g_forcedBase = static_cast<uintptr_t>(_strtoui64(argv[++i], nullptr, 16));
            continue;
        }
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, nameArg, MAX_PATH);
    }

    DWORD pid = 0;

    if (pidArg)
    {
        if (!exeNameForPid(pidArg))
        {
            printf("[!] pid %lu not found\n", pidArg);
            system("pause");
            return 1;
        }
        pid = pidArg;
        printf("[+] pid %lu  \"%ls\"\n", pid, g_procName);
    }
    else if (nameArg[0])
    {
        pid = findPidExact(nameArg);
        if (pid) wcscpy_s(g_procName, nameArg);
        else
        {
            pid = findPidKeyword(nameArg);
            if (pid) printf("[+] matched \"%ls\" (%lu)\n", g_procName, pid);
        }
    }
    else
    {
        pid = findPidKeyword(DEFAULT_KEYWORD);
        if (pid) printf("[+] auto-detected \"%ls\" (%lu)\n", g_procName, pid);
    }

    if (!pid)
    {
        printf("\n[!] target not found. windowed processes:\n\n");
        printList();
        system("pause");
        return 1;
    }

    if (!g_procName[0] && !exeNameForPid(pid))
    {
        printf("[!] could not resolve exe name for pid %lu\n", pid);
        system("pause");
        return 1;
    }

    if (!openTarget(pid))
    {
        printf("[!] could not open pid %lu\n", pid);
        system("pause");
        return 1;
    }

    loadNt();
    readFilePeInfo();

    if (doDiag)
    {
        diag(pid);
        system("pause");
        return 0;
    }

    bool haveBase = false;
    for (int i = 0; i < 3 && !haveBase; ++i)
    {
        haveBase = resolveModuleBase(pid);
        if (!haveBase) Sleep(150);
    }

    if (!haveBase)
    {
        printf("[!] all module base strategies failed\n");
        diag(pid);
        system("pause");
        return 1;
    }

    if (!g_size)
    {
        g_size = g_file.ok ? g_file.sizeOfImage : 0x8000000;
        printf("[!] size unknown, assuming 0x%zX\n", g_size);
    }
    else if (g_file.ok && g_file.sizeOfImage > g_size)
    {
        g_size = g_file.sizeOfImage;
    }

    printf("[+] base %p  size %zx  ptr %zu  header %s\n",
           (void*)g_base, g_size, g_ptrSize, probeHeader(g_base) ? "ok" : "erased");

    g_gameWnd = findGameWindow(pid);

    if (loot)
    {
        DumpLoot(findBattleUpdater(true));
        system("pause");
        return 0;
    }

    if (!guiMode)
    {
        uintptr_t bu = findBattleUpdater(true);
        printf("[+] battleUpdater %p\n", (void*)bu);
        InstantLoot(bu);
        printf("[+] done\n");
        system("pause");
        return 0;
    }

    // ---- gui mode
    if (!g_gameWnd)
    {
        printf("[!] no game window found - overlay will not follow\n");
    }

    createOverlay();
    createGui();
    installHooks();

    std::thread worker(workerThread);

    logf(L"attached to pid %lu (%s)", pid, g_procName);
    logf(L"press %s to open/close this menu", keyName(cfg.menuKey).c_str());

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_running = false;
    worker.detach();

    if (g_kbHook) UnhookWindowsHookEx(g_kbHook);
    if (g_msHook) UnhookWindowsHookEx(g_msHook);
    if (g_proc) CloseHandle(g_proc);

    saveConfig();
    return 0;
}
