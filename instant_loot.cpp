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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <cstdlib>
#include <vector>
#include <string>
#include <utility>
#include <algorithm>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

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

// ------------------------------------------------------------------ state
static HANDLE    g_proc = nullptr;
static uintptr_t g_base = 0;
static size_t    g_size = 0;
static wchar_t   g_procName[MAX_PATH] = L"";
static size_t    g_ptrSize = 8;
static bool      g_haveQI = false;

// ntdll equivalents that work without PROCESS_QUERY_INFORMATION
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

// ------------------------------------------------------------------ bitness
static void detectBitness()
{
    BOOL wow = FALSE;
    if (IsWow64Process(g_proc, &wow) && wow)
    {
        g_ptrSize = 4;
        printf("[+] target is 32-bit (WOW64)\n");
        return;
    }
    g_ptrSize = 8;
    printf("[+] target is 64-bit\n");
}

// ------------------------------------------------------------------ module base
static bool validateImageBase(uintptr_t base, size_t* sizeOut)
{
    if (!base) return false;

    IMAGE_DOS_HEADER dos{};
    if (!readRaw(base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) return false;

    IMAGE_NT_HEADERS32 nt{};
    if (!readRaw(base + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    if (!nt.OptionalHeader.SizeOfImage) return false;

    const WORD machine = nt.FileHeader.Machine;
    if (machine == IMAGE_FILE_MACHINE_I386)        g_ptrSize = 4;
    else if (machine == IMAGE_FILE_MACHINE_AMD64)  g_ptrSize = 8;
    else if (machine == IMAGE_FILE_MACHINE_ARM64)  g_ptrSize = 8;
    else return false;

    if (sizeOut) *sizeOut = nt.OptionalHeader.SizeOfImage;
    return true;
}

static bool baseFromToolhelp(DWORD pid)
{
    for (int attempt = 0; attempt < 3; ++attempt)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W me{ sizeof(me) };
            bool found = false;
            for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
            {
                if (_wcsicmp(me.szModule, g_procName) == 0)
                {
                    size_t size = 0;
                    if (validateImageBase(reinterpret_cast<uintptr_t>(me.modBaseAddr), &size))
                    {
                        g_base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                        g_size = size;
                        found  = true;
                        break;
                    }
                }
            }
            CloseHandle(snap);
            if (found) return true;
        }
        Sleep(20);
    }
    return false;
}

static bool baseFromPsapi()
{
    HMODULE mods[512]{};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(g_proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return false;
    if (needed < sizeof(HMODULE) || !mods[0]) return false;

    size_t size = 0;
    uintptr_t base = reinterpret_cast<uintptr_t>(mods[0]);
    if (!validateImageBase(base, &size)) return false;

    g_base = base;
    g_size = size;
    return true;
}

static bool baseFromPeb()
{
    using NtQIP = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntqip = reinterpret_cast<NtQIP>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntqip) return false;

    uintptr_t peb = 0;
    uintptr_t ldrOff, listOff, linksOff, dllBaseOff, nameLenOff, nameBufOff;

    if (g_ptrSize == 4)
    {
        ULONG_PTR peb32 = 0;
        if (ntqip(g_proc, 26, &peb32, sizeof(peb32), nullptr) < 0) return false;
        if (!peb32) return false;
        peb = static_cast<uintptr_t>(peb32);
        ldrOff = 0x0C; listOff = 0x14; linksOff = 0x08;
        dllBaseOff = 0x18; nameLenOff = 0x2C; nameBufOff = 0x30;
    }
    else
    {
        PROCESS_BASIC_INFORMATION pbi{};
        if (ntqip(g_proc, 0, &pbi, sizeof(pbi), nullptr) < 0) return false;
        if (!pbi.PebBaseAddress) return false;
        peb = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
        ldrOff = 0x18; listOff = 0x20; linksOff = 0x10;
        dllBaseOff = 0x30; nameLenOff = 0x58; nameBufOff = 0x60;
    }

    uintptr_t ldr = 0;
    if (!readPtr(peb + ldrOff, &ldr)) return false;

    const uintptr_t head = ldr + listOff;
    uintptr_t cur = 0;
    if (!readPtr(head, &cur)) return false;

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
                if (_wcsicmp(name, g_procName) == 0)
                {
                    size_t size = 0;
                    if (validateImageBase(dllBase, &size))
                    {
                        g_base = dllBase;
                        g_size = size;
                        return true;
                    }
                }
            }
        }
        readPtr(cur, &cur);
    }
    return false;
}

static bool baseFromImageScan()
{
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    uintptr_t lowest = 0;
    size_t lowestSize = 0;

    while (queryRegion(addr, &mbi))
    {
        if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT && mbi.AllocationBase)
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            size_t size = 0;
            if (validateImageBase(base, &size) && (lowest == 0 || base < lowest))
            {
                lowest = base;
                lowestSize = size;
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    if (!lowest) return false;
    g_base = lowest;
    g_size = lowestSize;
    return true;
}

static bool resolveModuleBase(DWORD pid)
{
    if (g_haveQI && baseFromToolhelp(pid)) { printf("[+] base via toolhelp\n"); return true; }
    if (g_haveQI && baseFromPsapi())       { printf("[+] base via psapi\n");    return true; }
    if (baseFromPeb())                     { printf("[+] base via PEB walk\n"); return true; }
    if (baseFromImageScan())               { printf("[+] base via image scan\n"); return true; }
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
    if (!battleUpdater)
        return;

    uintptr_t content = 0;
    if (!readPtr(battleUpdater + 0x68, &content))
        return;

    uintptr_t inst = 0;
    if (!readPtr(content + 0x540, &inst))
        return;

    write<float>(inst + 0x58, 0.0001f);

    uintptr_t list = 0;
    if (!readPtr(inst + 0x18, &list))
        return;

    uintptr_t items = 0;
    if (!readPtr(list + 0x10, &items))
        return;

    const int size = read<int>(list + 0x18);
    if (size <= 0 || size > 500)
        return;

    for (int i = 0; i < size; ++i)
    {
        const uintptr_t pair = items + 0x20 + (static_cast<uintptr_t>(i) * 0x18);

        uintptr_t desc = 0;
        if (!readPtr(pair + 0x10, &desc))
            continue;

        write<float>(desc + 0x40, 0.0f);
        write<float>(desc + 0x68, 0.0f);
    }
}

// ------------------------------------------------------------------ loot dump
// BattleEntitiesUpdater._battleEntitiesModel (0x18) -> _worldEntitiesModel (0x60)
// -> list offset -> elements -> position model -> X/Y/Z
static void dumpList(const char* label, uintptr_t world, uintptr_t listOff, uintptr_t posOff)
{
    uintptr_t list = 0;
    if (!readPtr(world + listOff, &list))
    {
        printf("  %s: no list\n", label);
        return;
    }

    uintptr_t items = 0;
    if (!readPtr(list + 0x10, &items))
    {
        printf("  %s: empty\n", label);
        return;
    }

    const int size = read<int>(list + 0x18);
    if (size <= 0 || size > 4096)
    {
        printf("  %s: bad size %d\n", label, size);
        return;
    }

    printf("  %s: %d entries\n", label, size);
    for (int i = 0; i < size; ++i)
    {
        uintptr_t ent = 0;
        if (!readPtr(items + 0x20 + (static_cast<uintptr_t>(i) * g_ptrSize), &ent))
            continue;

        uintptr_t pos = 0;
        if (!readPtr(ent + posOff, &pos))
            continue;

        printf("    [%3d] %11.2f %11.2f %11.2f\n",
               i, read<float>(pos + 0x10), read<float>(pos + 0x14), read<float>(pos + 0x18));
    }
}

static void DumpLoot(uintptr_t battleUpdater)
{
    if (!battleUpdater)
    {
        printf("[!] no battleUpdater\n");
        return;
    }

    uintptr_t entities = 0;
    if (!readPtr(battleUpdater + 0x18, &entities))
    {
        printf("[!] no battleEntitiesModel\n");
        return;
    }

    uintptr_t world = 0;
    if (!readPtr(entities + 0x60, &world))
    {
        printf("[!] no worldEntitiesModel\n");
        return;
    }

    dumpList("containers", world, 0x20, 0x28);
    dumpList("loots",      world, 0x38, 0x28);
    dumpList("vehicleLoot", world, 0x40, 0x28);
    dumpList("doors",      world, 0x48, 0x38);
}

// ------------------------------------------------------------------ diag
static void diag(DWORD pid)
{
    printf("=== diag pid %lu ===\n", pid);
    printf("elevated: %d\n", isElevated() ? 1 : 0);
    printf("SeDebugPrivilege: %d\n", enableDebugPrivilege() ? 1 : 0);

    struct { const char* n; DWORD r; } rights[] = {
        { "QUERY_INFORMATION",         PROCESS_QUERY_INFORMATION },
        { "QUERY_LIMITED_INFORMATION", PROCESS_QUERY_LIMITED_INFORMATION },
        { "VM_READ",                   PROCESS_VM_READ },
        { "VM_WRITE|VM_OP",            PROCESS_VM_WRITE | PROCESS_VM_OPERATION },
        { "VM_READ|QUERY_INFORMATION", PROCESS_VM_READ | PROCESS_QUERY_INFORMATION },
    };
    for (auto& r : rights)
    {
        SetLastError(0);
        HANDLE h = OpenProcess(r.r, FALSE, pid);
        printf("  %-28s %s (err %lu)\n", r.n, h ? "ok" : "FAIL", h ? 0UL : GetLastError());
        if (h) CloseHandle(h);
    }

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!g_proc) { printf("no usable handle\n"); return; }
    loadNt();

    printf("NtReadVirtualMemory: %s\n", g_ntRead ? "available" : "missing");
    printf("NtQueryVirtualMemory: %s\n", g_ntQueryVm ? "available" : "missing");

    SetLastError(0);
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    printf("  SNAPMODULE                   %s (err %lu)\n",
           s == INVALID_HANDLE_VALUE ? "FAIL" : "ok", s == INVALID_HANDLE_VALUE ? GetLastError() : 0UL);
    if (s != INVALID_HANDLE_VALUE) CloseHandle(s);

    HMODULE m[8]{};
    DWORD need = 0;
    SetLastError(0);
    BOOL ep = EnumProcessModulesEx(g_proc, m, sizeof(m), &need, LIST_MODULES_ALL);
    printf("  EnumProcessModulesEx         %s (err %lu, need %lu)\n",
           ep ? "ok" : "FAIL", ep ? 0UL : GetLastError(), need);

    MEMORY_BASIC_INFORMATION mbi{};
    SetLastError(0);
    BOOL vq = VirtualQueryEx(g_proc, reinterpret_cast<LPCVOID>(0), &mbi, sizeof(mbi));
    printf("  VirtualQueryEx(0)            %s (err %lu)\n", vq ? "ok" : "FAIL", vq ? 0UL : GetLastError());
    if (g_ntQueryVm)
    {
        SIZE_T got = 0;
        const NTSTATUS st = g_ntQueryVm(g_proc, reinterpret_cast<PVOID>(0), 0, &mbi, sizeof(mbi), &got);
        printf("  NtQueryVirtualMemory(0)      status 0x%08lX\n", static_cast<unsigned long>(st));
    }

    uintptr_t probe = 0;
    bool found = false;
    for (int i = 0; i < 5000; ++i)
    {
        if (!queryRegion(probe, &mbi)) break;
        if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT && mbi.AllocationBase)
        { probe = reinterpret_cast<uintptr_t>(mbi.AllocationBase); found = true; break; }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= probe) break;
        probe = next;
    }

    if (found)
    {
        uint8_t buf[8]{};
        SIZE_T got = 0;
        SetLastError(0);
        BOOL r = ReadProcessMemory(g_proc, reinterpret_cast<LPCVOID>(probe), buf, sizeof(buf), &got);
        printf("  ReadProcessMemory(%p)  %s (err %lu, got %zu)\n",
               reinterpret_cast<void*>(probe), r ? "ok" : "FAIL", r ? 0UL : GetLastError(), got);
        if (r) printf("  first bytes: %02X %02X %02X %02X\n", buf[0], buf[1], buf[2], buf[3]);
    }
    else printf("  no MEM_IMAGE region reachable\n");

    CloseHandle(g_proc);
    g_proc = nullptr;
}

// ------------------------------------------------------------------ main
int main(int argc, char** argv)
{
    SetConsoleTitleW(L"instant loot");

    if (!isElevated())
    {
        printf("[!] not elevated - requesting UAC\n");
        if (relaunchElevated()) return 0;
        printf("[!] relaunch failed (%lu), continuing unelevated\n", GetLastError());
    }
    if (!enableDebugPrivilege())
        printf("[!] SeDebugPrivilege not enabled (%lu)\n", GetLastError());

    bool watch = false, loot = false, doDiag = false;
    wchar_t nameArg[MAX_PATH] = L"";
    DWORD pidArg = 0;

    for (int i = 1; i < argc; ++i)
    {
        if (!_stricmp(argv[i], "--watch")) { watch = true; continue; }
        if (!_stricmp(argv[i], "--loot"))  { loot = true; continue; }
        if (!_stricmp(argv[i], "--diag"))  { doDiag = true; continue; }
        if (!_stricmp(argv[i], "--list"))  { printList(); system("pause"); return 0; }
        if (!_stricmp(argv[i], "--pid") && i + 1 < argc)
        {
            pidArg = static_cast<DWORD>(strtoul(argv[++i], nullptr, 10));
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
        if (pid)
            wcscpy_s(g_procName, nameArg);
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

    if (doDiag)
    {
        diag(pid);
        system("pause");
        return 0;
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
    detectBitness();

    bool haveBase = false;
    for (int i = 0; i < 10 && !haveBase; ++i)
    {
        haveBase = resolveModuleBase(pid);
        if (!haveBase) Sleep(150);
    }
    if (!haveBase)
    {
        printf("[!] all module base strategies failed\n");
        printf("    run: instant_loot.exe --pid %lu --diag\n", pid);
        system("pause");
        return 1;
    }

    printf("[+] base %p  size %zx  ptr %zu\n", (void*)g_base, g_size, g_ptrSize);

    if (loot)
    {
        DumpLoot(findBattleUpdater(true));
        system("pause");
        return 0;
    }

    if (!watch)
    {
        uintptr_t bu = findBattleUpdater(true);
        printf("[+] battleUpdater %p\n", (void*)bu);
        InstantLoot(bu);
        printf("[+] done\n");
        system("pause");
        return 0;
    }

    printf("[+] watch mode, Ctrl+C to stop\n");
    bool reported = false;
    for (;;)
    {
        uintptr_t bu = findBattleUpdater(!reported);
        reported = (bu != 0);
        InstantLoot(bu);
        Sleep(WATCH_INTERVAL);
    }
}
