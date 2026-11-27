// instant_loot.cpp  —  build x64, run as admin
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
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

// ------------------------------------------------------------------ config
// Fallback keyword used when no process name is given on the command line.
static const wchar_t* DEFAULT_KEYWORD = L"ROB RUN";

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

// One EnumWindows pass: pid -> first visible non-empty window title.
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
    printf("\nusage: instant_loot.exe <exe name | --pid N> [--watch]\n");
}

static DWORD findPidExact(const wchar_t* name)
{
    for (auto& c : snapshotProcs(false))
        if (_wcsicmp(c.exe.c_str(), name) == 0) return c.pid;
    return 0;
}

// Higher score = better evidence. exe name always beats window title.
static int scoreMatch(const std::wstring& exe, const std::wstring& title, const std::wstring& key)
{
    int s = 0;
    if (exe == key || exe == key + L"exe") s = 100;   // "robrun" / "robrunexe"
    else if (exe.rfind(key, 0) == 0)       s = 60;    // exe starts with key
    else if (wcontains(exe, key))          s = 40;    // exe contains key
    if (wcontains(title, key)) s = (std::max)(s, 5);  // title-only = weakest
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

static uintptr_t findBattleUpdater(bool verbose)
{
#if USE_SIGNATURE
    std::vector<int> pat;
    if (!parsePattern(BUPDATER_PATTERN, pat)) { printf("[!] bad pattern\n"); return 0; }

    uintptr_t hit = scanPattern(pat);
    if (!hit) { if (verbose) printf("[!] pattern not found\n"); return 0; }

    // mov rax, [rip+disp32] -> resolve the displacement against the end of the
    // 7-byte instruction, then deref the global slot to get the object.
    const int32_t disp = read<int32_t>(hit + BUPDATER_PATTERN_OFFSET);
    const uintptr_t slot = hit + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(disp));
    const uintptr_t obj  = read<uintptr_t>(slot);
    return BUPDATER_PATTERN_DEREF ? obj : slot;
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
    wchar_t nameArg[MAX_PATH] = L"";
    DWORD pidArg = 0;

    for (int i = 1; i < argc; ++i)
    {
        if (!_stricmp(argv[i], "--watch")) { watch = true; continue; }
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
            pid = findPidKeyword(nameArg);          // sets g_procName itself on success
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

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                         | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_proc)
    {
        printf("[!] OpenProcess failed (%lu) - run as admin\n", GetLastError());
        system("pause");
        return 1;
    }

    if (!resolveModuleBase(pid, g_procName))
    {
        printf("[!] module base lookup failed (%lu)\n", GetLastError());
        system("pause");
        return 1;
    }

    printf("[+] base %p  size %zx\n", (void*)g_base, g_size);

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
