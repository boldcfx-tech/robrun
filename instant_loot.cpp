// instant_loot.cpp  —  build x64 (or x86 to match the game), run as admin
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <vector>
#include <string>

#pragma comment(lib, "user32.lib")

// ------------------------------------------------------------------ config
// Fallback keyword used when no process name is given on the command line.
static const wchar_t* DEFAULT_KEYWORD = L"robrun";

#define USE_SIGNATURE   1

static const char* BUPDATER_PATTERN = "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ??";

static const int  BUPDATER_PATTERN_OFFSET = 3;

static const bool BUPDATER_PATTERN_DEREF  = true;

static const uintptr_t BUPDATER_STATIC_RVA = 0x0000000;

static const DWORD WATCH_INTERVAL = 100;

// ------------------------------------------------------------------ memory
static HANDLE    g_proc = nullptr;
static uintptr_t g_base = 0;
static size_t    g_size = 0;
static wchar_t   g_procName[MAX_PATH] = L"";

template <typename T>
static T read(uintptr_t addr)
{
    T out{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(g_proc, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &got)
        || got != sizeof(T))
        out = T{};
    return out;
}

template <typename T>
static bool write(uintptr_t addr, T value)
{
    SIZE_T put = 0;
    return WriteProcessMemory(g_proc, reinterpret_cast<LPVOID>(addr), &value, sizeof(T), &put)
           && put == sizeof(T);
}

// ------------------------------------------------------------------ process
struct Cand { DWORD pid; std::wstring exe; std::wstring title; };

static bool hasWindow(DWORD pid)
{
    struct Ctx { DWORD pid; bool found; } ctx{ pid, false };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = reinterpret_cast<Ctx*>(lp);
        DWORD owner = 0;
        GetWindowThreadProcessId(h, &owner);
        if (owner == c->pid && IsWindowVisible(h) && GetWindow(h, GW_OWNER) == nullptr)
        {
            c->found = true;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

static std::wstring windowTitle(DWORD pid)
{
    struct Ctx { DWORD pid; std::wstring title; } ctx{ pid, L"" };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = reinterpret_cast<Ctx*>(lp);
        DWORD owner = 0;
        GetWindowThreadProcessId(h, &owner);
        if (owner == c->pid && IsWindowVisible(h))
        {
            wchar_t buf[256]{};
            GetWindowTextW(h, buf, 255);
            if (buf[0]) { c->title = buf; return FALSE; }
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.title;
}

static std::vector<Cand> snapshotProcs()
{
    std::vector<Cand> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        out.push_back({ pe.th32ProcessID, pe.szExeFile, L"" });

    CloseHandle(snap);
    return out;
}

static bool wcontains(const wchar_t* hay, const wchar_t* needle)
{
    if (!*needle) return true;
    for (const wchar_t* h = hay; *h; ++h)
    {
        const wchar_t* a = h;
        const wchar_t* b = needle;
        while (*a && *b && towlower(*a) == towlower(*b)) { ++a; ++b; }
        if (!*b) return true;
    }
    return false;
}

static DWORD findPidExact(const wchar_t* name)
{
    for (auto& c : snapshotProcs())
        if (_wcsicmp(c.exe.c_str(), name) == 0) return c.pid;
    return 0;
}

static DWORD findPidKeyword(const wchar_t* keyword)
{
    std::vector<Cand> hits;
    for (auto& c : snapshotProcs())
    {
        if (c.pid == GetCurrentProcessId()) continue;
        if (wcontains(c.exe.c_str(), keyword)) hits.push_back(c);
    }
    if (hits.size() == 1) { wcscpy_s(g_procName, hits[0].exe.c_str()); return hits[0].pid; }

    if (hits.empty()) return 0;

    printf("[?] %zu matches for \"%ls\" - pass one explicitly:\n", hits.size(), keyword);
    for (auto& c : hits) printf("    %lu  %ls\n", c.pid, c.exe.c_str());
    return 0;
}

static bool resolveModuleBase(DWORD pid, const wchar_t* module)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
    {
        if (_wcsicmp(me.szModule, module) == 0)
        {
            g_base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            g_size = me.modBaseSize;
            found  = true;
            break;
        }
    }
    CloseHandle(snap);
    return found;
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
    SIZE_T got = 0;
    if (!ReadProcessMemory(g_proc, reinterpret_cast<LPCVOID>(g_base), buf.data(), g_size, &got)
        || got == 0)
        return 0;

    const size_t n = pat.size();
    if (got < n) return 0;

    for (size_t i = 0; i + n <= got; ++i)
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

static uintptr_t findBattleUpdater()
{
#if USE_SIGNATURE
    std::vector<int> pat;
    if (!parsePattern(BUPDATER_PATTERN, pat)) { printf("[!] bad pattern\n"); return 0; }

    uintptr_t hit = scanPattern(pat);
    if (!hit) { printf("[!] pattern not found\n"); return 0; }

    uintptr_t addr = hit + BUPDATER_PATTERN_OFFSET;
    return BUPDATER_PATTERN_DEREF ? read<uintptr_t>(addr) : addr;
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

    // BattleEntitiesUpdater -> BattleScreenContent -> InventoryRevealViewDescriptions
    uintptr_t content = read<uintptr_t>(battleUpdater + 0x68);
    if (!content)
        return;

    uintptr_t inst = read<uintptr_t>(content + 0x540);
    if (!inst)
        return;

    // Delay between cells on the main instance (TimeToOneCellBorder)
    write<float>(inst + 0x58, 0.0001f);

    // List<Pair> at +0x18
    uintptr_t list = read<uintptr_t>(inst + 0x18);
    if (!list)
        return;

    uintptr_t items = read<uintptr_t>(list + 0x10);
    int size = read<int>(list + 0x18);
    if (!items || size <= 0 || size > 500)
        return;

    // Loop items (stride 0x18, Description* at +0x10)
    for (int i = 0; i < size; ++i)
    {
        uintptr_t pair = items + 0x20 + (i * 0x18);
        uintptr_t desc = read<uintptr_t>(pair + 0x10);
        if (!desc)
            continue;

        // Shine Duration (inline struct 0x18 + 0x28)
        write<float>(desc + 0x40, 0.0f);

        // Icon Duration (inline struct 0x50 + 0x18)
        write<float>(desc + 0x68, 0.0f);
    }
}

// ------------------------------------------------------------------ main
int main(int argc, char** argv)
{
    SetConsoleTitleW(L"instant loot");

    bool watch = false;
    bool list  = false;
    wchar_t nameArg[MAX_PATH] = L"";

    for (int i = 1; i < argc; ++i)
    {
        if (!_stricmp(argv[i], "--watch")) { watch = true; continue; }
        if (!_stricmp(argv[i], "--list"))  { list  = true; continue; }
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, nameArg, MAX_PATH);
    }

    if (list)
    {
        printf("pid      exe                             title\n");
        printf("---------------------------------------------------------------\n");
        for (auto& c : snapshotProcs())
        {
            if (c.pid == GetCurrentProcessId()) continue;
            if (!hasWindow(c.pid)) continue;
            printf("%-8lu %-31ls %ls\n", c.pid, c.exe.c_str(), windowTitle(c.pid).c_str());
        }
        printf("\nusage: instant_loot.exe <exe name> [--watch]\n");
        system("pause");
        return 0;
    }

    DWORD pid = 0;
    if (nameArg[0])
    {
        wcscpy_s(g_procName, nameArg);
        pid = findPidExact(nameArg);
        if (!pid)
        {
            printf("[!] no process named \"%ls\"\n", nameArg);
            DWORD guess = findPidKeyword(nameArg);
            if (guess) { pid = guess; printf("[+] using \"%ls\" (%lu)\n", g_procName, pid); }
        }
    }
    else
    {
        pid = findPidKeyword(DEFAULT_KEYWORD);
        if (pid) printf("[+] auto-detected \"%ls\" (%lu)\n", g_procName, pid);
    }

    if (!pid)
    {
        printf("[!] target not found - run with --list to see real names\n");
        system("pause");
        return 1;
    }

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                         | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_proc)
    {
        printf("[!] OpenProcess failed (%lu) - run as admin, and match bitness\n", GetLastError());
        system("pause");
        return 1;
    }

    if (!resolveModuleBase(pid, g_procName))
    {
        printf("[!] module base lookup failed (%lu)\n", GetLastError());
        system("pause");
        return 1;
    }

    printf("[+] pid %lu  base %p  size %zx\n", pid, (void*)g_base, g_size);

    if (!watch)
    {
        uintptr_t bu = findBattleUpdater();
        printf("[+] battleUpdater %p\n", (void*)bu);
        InstantLoot(bu);
        printf("[+] done\n");
        system("pause");
        return 0;
    }

    printf("[+] watch mode, Ctrl+C to stop\n");
    for (;;)
    {
        InstantLoot(findBattleUpdater());
        Sleep(WATCH_INTERVAL);
    }
}
