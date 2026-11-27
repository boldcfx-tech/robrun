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
static const wchar_t* GAME_ASSEMBLY   = L"GameAssembly.dll";

// verified against robrun_offsets.json / robrun_sdk_offsets.json
enum : uintptr_t
{
    OFF_UPD_BEM        = 0x18,   // BattleEntitiesUpdater._battleEntitiesModel
    OFF_UPD_BATTLE     = 0x70,   // BattleEntitiesUpdater._battleModel
    OFF_UPD_BATTLE_ALT = 0x68,   // older battleUpdater+content path

    OFF_BATTLE_ENTS    = 0x90,   // BattleModel.BattleEntitiesModel
    OFF_BATTLE_CAM     = 0x358,  // BattleModel.BattleCameraModel
    OFF_BEM_WORLD      = 0x60,   // BattleEntitiesModel._worldEntitiesModel

    OFF_WEM_CHARS      = 0x18,   // WorldEntitiesModel._battleCharacters (Dictionary)
    OFF_WEM_CONTAINERS = 0x20,   // WorldEntitiesModel._containers
    OFF_WEM_LOOTS      = 0x38,   // WorldEntitiesModel._loots
    OFF_WEM_VLOOTS     = 0x40,   // WorldEntitiesModel._vehicleLoots
    OFF_WEM_DOORS      = 0x48,   // WorldEntitiesModel._doors

    OFF_CONTAINER_POS  = 0x28,   // ContainerModel.PositionModel
    OFF_LOOT_POS       = 0x28,   // LootModel.InteractPositionModel
    OFF_VLOOT_POS      = 0x28,   // VehicleLootModel.InteractPositionModel
    OFF_DOOR_POS       = 0x38,   // DoorModel.Position

    OFF_CHAR_TRANSFORM = 0x58,   // BattleCharacterModel.Transform
    OFF_CHAR_DATA      = 0x40,   // BattleCharacterModel.Data
    OFF_CHAR_DEAD      = 0xF0,   // BattleCharacterModel.IsDead

    OFF_DATA_PRIV      = 0x28,   // BattleCharacterData.PrivateData
    OFF_PRIV_HEALTH    = 0x38,   // BattleCharacterPrivateData.Health

    OFF_CAM_POS        = 0x10,
    OFF_CAM_FWD        = 0x3C,
    OFF_CAM_RIGHT      = 0x48,
    OFF_CAM_UP         = 0x54,
    OFF_CAM_DIST       = 0x60,

    OFF_POS_X          = 0x10,   // PositionModel / CharacterTransformModel
    OFF_POS_Y          = 0x14,
    OFF_POS_Z          = 0x18,

    // static field globals, RVA inside GameAssembly.dll
    RVA_CAMERA_STATIC  = 136002712,
    RVA_WORLD_STATIC   = 136036160,

    // generic IL2CPP object layout
    OFF_DICT_ENTRIES   = 0x18,
    OFF_DICT_COUNT     = 0x20,
    OFF_LIST_ITEMS     = 0x10,
    OFF_LIST_SIZE      = 0x18,
    OFF_ARRAY_LENGTH   = 0x18,
    OFF_ENTRY_VALUE    = 0x10,
    ENTRY_STRIDE       = 0x18,
};

static const char* UPDATER_PATTERN_64 = "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ??";
static const int   UPDATER_PATTERN_OFFSET_64 = 3;

enum { T_PLAYER = 0, T_CONTAINER = 1, T_LOOT = 2, T_VLOOT = 3, T_DOOR = 4 };

struct Config
{
    bool esp = false, aim = false, instantLoot = true;
    bool aimHoldMode = true;
    bool drawBox = true, drawDist = true, drawHealth = true, drawSnapline = false;
    bool drawPlayers = true, drawContainers = false, drawLoot = false, drawDoors = false;

    int aimFov = 130, smooth = 22, espFov = 70, maxDist = 250;
    int menuKey = VK_RSHIFT, espKey = VK_F1, aimKey = VK_F2, holdKey = VK_XBUTTON2;
    int heightX10 = 18;
};
static Config cfg;

// ------------------------------------------------------------------ state
static HANDLE    g_proc = nullptr;
static uintptr_t g_base = 0;      // ROB RUN.exe (diag only)
static size_t    g_size = 0;
static uintptr_t g_gaBase = 0;    // GameAssembly.dll
static size_t    g_gaSize = 0;
static wchar_t   g_procName[MAX_PATH] = L"";
static wchar_t   g_gameDir[MAX_PATH * 2] = L"";
static bool      g_haveQI = false;
static uintptr_t g_forcedBase = 0;

static std::atomic<bool> g_running{ true };

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
    if (ReadProcessMemory(g_proc, reinterpret_cast<LPCVOID>(addr), buf, len, &got) && got == len) return true;
    got = 0;
    if (g_ntRead && g_ntRead(g_proc, reinterpret_cast<PVOID>(addr), buf, len, &got) >= 0 && got == len) return true;
    return false;
}

template <typename T> static T read(uintptr_t a) { T o{}; readRaw(a, &o, sizeof(T)); return o; }

template <typename T> static bool write(uintptr_t a, T v)
{
    SIZE_T p = 0;
    return WriteProcessMemory(g_proc, reinterpret_cast<LPVOID>(a), &v, sizeof(T), &p) && p == sizeof(T);
}

static bool readPtr(uintptr_t a, uintptr_t* o)
{
    const uint64_t v = read<uint64_t>(a);
    *o = static_cast<uintptr_t>(v);
    return v > 0x10000 && v < 0x00007FFFFFFF0000ULL;
}

static bool queryRegion(uintptr_t a, MEMORY_BASIC_INFORMATION* m)
{
    if (g_ntQueryVm)
    {
        SIZE_T g = 0;
        if (g_ntQueryVm(g_proc, reinterpret_cast<PVOID>(a), 0, m, sizeof(*m), &g) >= 0) return true;
    }
    return VirtualQueryEx(g_proc, reinterpret_cast<LPCVOID>(a), m, sizeof(*m)) == sizeof(*m);
}

// ------------------------------------------------------------------ elevation
static bool isElevated()
{
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return false;
    TOKEN_ELEVATION e{}; DWORD cb = sizeof(e);
    bool r = GetTokenInformation(t, TokenElevation, &e, sizeof(e), &cb) && e.TokenIsElevated;
    CloseHandle(t); return r;
}

static bool relaunchElevated()
{
    wchar_t exe[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return false;
    std::wstring p;
    for (int i = 1; i < __argc; ++i) { p += L'"'; p += __wargv[i]; p += L"\" "; }
    SHELLEXECUTEINFOW s{ sizeof(s) };
    s.fMask = SEE_MASK_NOCLOSEPROCESS; s.lpVerb = L"runas"; s.lpFile = exe;
    s.lpParameters = p.empty() ? nullptr : p.c_str(); s.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&s)) return false;
    if (s.hProcess) CloseHandle(s.hProcess);
    return true;
}

static bool enableDebugPrivilege()
{
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return false;
    LUID l{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &l)) { CloseHandle(t); return false; }
    TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = l;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(0);
    bool ok = AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == 0;
    CloseHandle(t); return ok;
}

// ------------------------------------------------------------------ process
struct Cand { DWORD pid; std::wstring exe; std::wstring title; };

static std::wstring normalize(const wchar_t* s)
{
    std::wstring o;
    for (; *s; ++s) if (iswalnum(*s)) o.push_back(static_cast<wchar_t>(towlower(*s)));
    return o;
}

static bool wcontains(const std::wstring& h, const std::wstring& n)
{
    if (n.empty()) return true;
    if (h.size() < n.size()) return false;
    for (size_t i = 0; i + n.size() <= h.size(); ++i) if (h.compare(i, n.size(), n) == 0) return true;
    return false;
}

static std::vector<std::pair<DWORD, std::wstring>> windowTitles()
{
    std::vector<std::pair<DWORD, std::wstring>> o;
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* v = reinterpret_cast<std::vector<std::pair<DWORD, std::wstring>>*>(lp);
        if (!IsWindowVisible(h) || GetWindow(h, GW_OWNER)) return TRUE;
        DWORD p = 0; GetWindowThreadProcessId(h, &p);
        if (!p) return TRUE;
        wchar_t b[512]{};
        if (!GetWindowTextW(h, b, 511)) return TRUE;
        for (auto& e : *v) if (e.first == p) return TRUE;
        v->push_back({ p, b });
        return TRUE;
    }, reinterpret_cast<LPARAM>(&o));
    return o;
}

static std::vector<Cand> snapshotProcs(bool titles)
{
    std::vector<Cand> o;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return o;
    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL ok = Process32FirstW(s, &pe); ok; ok = Process32NextW(s, &pe))
        if (pe.th32ProcessID != GetCurrentProcessId()) o.push_back({ pe.th32ProcessID, pe.szExeFile, L"" });
    CloseHandle(s);
    if (titles)
    {
        auto t = windowTitles();
        for (auto& c : o) for (auto& x : t) if (x.first == c.pid) { c.title = x.second; break; }
        std::vector<Cand> w;
        for (auto& c : o) if (!c.title.empty()) w.push_back(c);
        return w;
    }
    return o;
}

static void printList()
{
    printf("pid      exe                             title\n");
    printf("---------------------------------------------------------------\n");
    for (auto& c : snapshotProcs(true)) printf("%-8lu %-31ls %.60ls\n", c.pid, c.exe.c_str(), c.title.c_str());
}

static DWORD findPidExact(const wchar_t* n)
{
    for (auto& c : snapshotProcs(false)) if (_wcsicmp(c.exe.c_str(), n) == 0) return c.pid;
    return 0;
}

static int scoreMatch(const std::wstring& e, const std::wstring& t, const std::wstring& k)
{
    int s = 0;
    if (e == k || e == k + L"exe") s = 100;
    else if (e.rfind(k, 0) == 0) s = 60;
    else if (wcontains(e, k)) s = 40;
    if (wcontains(t, k)) s = (std::max)(s, 5);
    return s;
}

static DWORD findPidKeyword(const wchar_t* kw)
{
    const std::wstring k = normalize(kw);
    if (k.empty()) return 0;
    std::vector<Cand> h; std::vector<int> sc;
    for (auto& c : snapshotProcs(true))
    {
        int s = scoreMatch(normalize(c.exe.c_str()), normalize(c.title.c_str()), k);
        if (s) { h.push_back(c); sc.push_back(s); }
    }
    if (h.empty()) return 0;
    const int best = *std::max_element(sc.begin(), sc.end());
    std::vector<size_t> top;
    for (size_t i = 0; i < h.size(); ++i) if (sc[i] == best) top.push_back(i);
    if (top.size() == 1) { wcscpy_s(g_procName, h[top[0]].exe.c_str()); return h[top[0]].pid; }
    printf("[?] ambiguous, use --pid:\n");
    for (size_t i : top) printf("    %lu  %-31ls %.60ls\n", h[i].pid, h[i].exe.c_str(), h[i].title.c_str());
    return 0;
}

static bool exeNameForPid(DWORD pid)
{
    for (auto& c : snapshotProcs(false)) if (c.pid == pid) { wcscpy_s(g_procName, c.exe.c_str()); return true; }
    return false;
}

static bool openTarget(DWORD pid)
{
    struct { const char* l; DWORD r; bool qi; } t[] = {
        { "rw+q",  PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, true },
        { "rw+ql", PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, false },
        { "r+ql",  PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false },
    };
    for (auto& x : t)
    {
        g_proc = OpenProcess(x.r, FALSE, pid);
        if (g_proc) { g_haveQI = x.qi; printf("[+] handle %s\n", x.l); return true; }
        printf("[!] OpenProcess(0x%08lX) failed (%lu)\n", x.r, GetLastError());
    }
    return false;
}

// ------------------------------------------------------------------ modules
static bool plausibleBase(uintptr_t b) { return b && (b & 0xFFF) == 0 && b < 0x00007FFFFFFF0000ULL; }

static bool moduleNamed(uintptr_t addr, const wchar_t* want)
{
    wchar_t p[MAX_PATH * 2]{};
    if (!GetMappedFileNameW(g_proc, reinterpret_cast<LPVOID>(addr), p, _countof(p))) return false;
    const wchar_t* t = wcsrchr(p, L'\\');
    return _wcsicmp(t ? t + 1 : p, want) == 0;
}

static size_t sizeFromDisk(const wchar_t* path)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 0;
    IMAGE_DOS_HEADER d{};
    DWORD g = 0;
    size_t out = 0;
    if (ReadFile(f, &d, sizeof(d), &g, nullptr) && d.e_magic == IMAGE_DOS_SIGNATURE &&
        SetFilePointer(f, d.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
    {
        IMAGE_NT_HEADERS64 n{};
        if (ReadFile(f, &n, sizeof(n), &g, nullptr) && n.Signature == IMAGE_NT_SIGNATURE)
            out = n.OptionalHeader.SizeOfImage;
    }
    CloseHandle(f);
    return out;
}

static bool baseFromToolhelp(DWORD pid, const wchar_t* name, uintptr_t* base, size_t* size)
{
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool f = false;
    for (BOOL ok = Module32FirstW(s, &me); ok; ok = Module32NextW(s, &me))
    {
        if (_wcsicmp(me.szModule, name)) continue;
        const uintptr_t b = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        if (!plausibleBase(b)) continue;
        *base = b; *size = me.modBaseSize; f = true; break;
    }
    CloseHandle(s);
    return f;
}

static bool baseFromPsapi(const wchar_t* name, uintptr_t* base)
{
    HMODULE m[1024]{};
    DWORD need = 0;
    if (!EnumProcessModulesEx(g_proc, m, sizeof(m), &need, LIST_MODULES_ALL)) return false;
    const DWORD n = (std::min)(need, static_cast<DWORD>(sizeof(m))) / sizeof(HMODULE);
    for (DWORD i = 0; i < n; ++i)
    {
        wchar_t b[MAX_PATH]{};
        if (!GetModuleBaseNameW(g_proc, m[i], b, MAX_PATH)) continue;
        if (_wcsicmp(b, name)) continue;
        const uintptr_t a = reinterpret_cast<uintptr_t>(m[i]);
        if (!plausibleBase(a)) continue;
        *base = a; return true;
    }
    return false;
}

static bool baseFromPeb(const wchar_t* name, uintptr_t* base)
{
    using NtQIP = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto q = reinterpret_cast<NtQIP>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!q) return false;
    PROCESS_BASIC_INFORMATION pbi{};
    if (q(g_proc, 0, &pbi, sizeof(pbi), nullptr) < 0 || !pbi.PebBaseAddress) return false;
    const uintptr_t peb = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
    uintptr_t ldr = 0;
    if (!readPtr(peb + 0x18, &ldr)) return false;
    const uintptr_t head = ldr + 0x20;
    uintptr_t cur = 0;
    if (!readPtr(head, &cur)) return false;
    for (int i = 0; i < 1024 && cur && cur != head; ++i)
    {
        const uintptr_t e = cur - 0x10;
        uintptr_t db = 0, nb = 0;
        const USHORT nl = read<USHORT>(e + 0x58);
        if (readPtr(e + 0x30, &db) && nl && nl < 512 && readPtr(e + 0x60, &nb))
        {
            wchar_t nm[256]{};
            if (readRaw(nb, nm, nl))
            {
                nm[nl / 2] = 0;
                if (_wcsicmp(nm, name) == 0 && plausibleBase(db)) { *base = db; return true; }
            }
        }
        if (!readPtr(cur, &cur)) break;
    }
    return false;
}

static bool baseFromImageScan(const wchar_t* name, uintptr_t* base)
{
    MEMORY_BASIC_INFORMATION m{};
    uintptr_t a = 0;
    while (queryRegion(a, &m))
    {
        if (m.Type == MEM_IMAGE && m.State == MEM_COMMIT && m.AllocationBase)
        {
            const uintptr_t b = reinterpret_cast<uintptr_t>(m.AllocationBase);
            if (plausibleBase(b) && moduleNamed(b, name)) { *base = b; return true; }
        }
        const uintptr_t nx = reinterpret_cast<uintptr_t>(m.BaseAddress) + m.RegionSize;
        if (nx <= a) break;
        a = nx;
    }
    return false;
}

static bool findModule(DWORD pid, const wchar_t* name, uintptr_t* base, size_t* size)
{
    *base = 0; if (size) *size = 0;
    if (g_haveQI && baseFromToolhelp(pid, name, base, size)) { printf("[+] %ls via toolhelp\n", name); return true; }
    if (g_haveQI && baseFromPsapi(name, base)) { printf("[+] %ls via psapi\n", name); return true; }
    if (baseFromPeb(name, base)) { printf("[+] %ls via PEB\n", name); return true; }
    if (baseFromImageScan(name, base)) { printf("[+] %ls via image scan\n", name); return true; }
    printf("[!] %ls not found\n", name);
    return false;
}

// ------------------------------------------------------------------ pattern
static bool parsePattern(const char* in, std::vector<int>& out)
{
    out.clear();
    for (const char* p = in; *p;)
    {
        if (*p == ' ') { ++p; continue; }
        if (p[0] == '?' && p[1] == '?') { out.push_back(-1); p += 2; continue; }
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int h = nib(p[0]), l = p[1] ? nib(p[1]) : -1;
        if (h < 0 || l < 0) return false;
        out.push_back((h << 4) | l);
        p += 2;
    }
    return !out.empty();
}

static uintptr_t scanModule(const std::vector<int>& pat)
{
    if (!g_gaBase || !g_gaSize) return 0;
    std::vector<uint8_t> b(g_gaSize);
    if (!readRaw(g_gaBase, b.data(), g_gaSize)) return 0;
    const size_t n = pat.size();
    for (size_t i = 0; i + n <= b.size(); ++i)
    {
        bool hit = true;
        for (size_t j = 0; j < n; ++j) if (pat[j] >= 0 && b[i + j] != (uint8_t)pat[j]) { hit = false; break; }
        if (hit) return g_gaBase + i;
    }
    return 0;
}

static uintptr_t updaterFromPattern()
{
    std::vector<int> p;
    if (!parsePattern(UPDATER_PATTERN_64, p)) return 0;
    const uintptr_t hit = scanModule(p);
    if (!hit) return 0;
    const int32_t disp = read<int32_t>(hit + UPDATER_PATTERN_OFFSET_64);
    const uintptr_t slot = hit + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(disp));
    return read<uintptr_t>(slot);
}

// ==================================================================
//  game structures
// ==================================================================
struct Vec3 { float x, y, z; };

static Vec3  g_camPos{}, g_camFwd{}, g_camRight{}, g_camUp{};
static float g_camDist = 0.0f;
static bool  g_camOk = false;

static uintptr_t g_camModel = 0;
static uintptr_t g_world = 0;
static uintptr_t g_updater = 0;
static DWORD     g_lastStatic = 0;
static DWORD     g_lastUpdScan = 0;

static bool finite(float f) { return f == f && fabsf(f) < 1e7f; }

static bool readVec(uintptr_t a, Vec3* v)
{
    float t[3]{};
    if (!readRaw(a, t, sizeof(t))) return false;
    if (!finite(t[0]) || !finite(t[1]) || !finite(t[2])) return false;
    v->x = t[0]; v->y = t[1]; v->z = t[2];
    return true;
}

static bool validCameraModel(uintptr_t m)
{
    Vec3 p{}, f{};
    if (!readVec(m + OFF_CAM_POS, &p) || !readVec(m + OFF_CAM_FWD, &f)) return false;
    if (fabsf(p.x) < 1e-4f && fabsf(p.y) < 1e-4f && fabsf(p.z) < 1e-4f) return false;
    const float len = sqrtf(f.x * f.x + f.y * f.y + f.z * f.z);
    return len > 0.9f && len < 1.1f;
}

// dictionary of int -> model, entries validated before use
static bool dictShape(uintptr_t dict, uintptr_t* entries, int* count)
{
    if (!readPtr(dict + OFF_DICT_ENTRIES, entries)) return false;
    const int c = read<int>(dict + OFF_DICT_COUNT);
    if (c <= 0 || c > 4096) return false;
    const int alen = read<int>(*entries + OFF_ARRAY_LENGTH);
    if (alen <= 0 || alen > 100000) return false;
    *count = (std::min)(c, alen);
    return true;
}

static bool validWorld(uintptr_t w)
{
    uintptr_t d = 0, e = 0;
    int c = 0;
    if (!readPtr(w + OFF_WEM_CHARS, &d)) return false;
    if (!dictShape(d, &e, &c)) return false;
    for (int i = 0; i < (std::min)(c, 8); ++i)
    {
        uintptr_t ch = 0;
        if (!readPtr(e + 0x20 + (uintptr_t)i * ENTRY_STRIDE + OFF_ENTRY_VALUE, &ch)) continue;
        uintptr_t tr = 0;
        if (!readPtr(ch + OFF_CHAR_TRANSFORM, &tr)) continue;
        Vec3 p{};
        if (readVec(tr + OFF_POS_X, &p)) return true;
    }
    return false;
}

static uintptr_t resolveStatic(uintptr_t rva, bool (*validate)(uintptr_t))
{
    if (!g_gaBase || !rva) return 0;
    uintptr_t p = 0;
    if (!readPtr(g_gaBase + rva, &p)) return 0;
    if (validate(p)) return p;
    static const uintptr_t drifts[] = { 0xB8, 0xB0, 0xC0, 0xA8, 0xC8 };
    for (uintptr_t d : drifts)
    {
        uintptr_t q = 0;
        if (!readPtr(p + d, &q)) continue;
        if (validate(q)) return q;
    }
    return 0;
}

static void refreshStatics()
{
    const DWORD now = GetTickCount();
    if (now - g_lastStatic < 1500) return;
    g_lastStatic = now;

    if (!g_gaBase)
    {
        uintptr_t b = 0; size_t s = 0;
        if (!findModule(GetProcessId(g_proc), GAME_ASSEMBLY, &b, &s)) return;
        g_gaBase = b;
        g_gaSize = s;
        if (!g_gaSize)
        {
            wchar_t path[MAX_PATH * 2]{};
            wcscpy_s(path, g_gameDir);
            wcscat_s(path, GAME_ASSEMBLY);
            g_gaSize = sizeFromDisk(path);
        }
        printf("[+] GameAssembly base %p size %zx\n", (void*)g_gaBase, g_gaSize);
    }

    if (!g_camModel || !validCameraModel(g_camModel))
    {
        g_camModel = resolveStatic(RVA_CAMERA_STATIC, validCameraModel);
        if (g_camModel) printf("[+] camera model %p\n", (void*)g_camModel);
    }
    if (!g_world || !validWorld(g_world))
    {
        g_world = resolveStatic(RVA_WORLD_STATIC, validWorld);
        if (g_world) printf("[+] world entities %p\n", (void*)g_world);
    }

    if (g_camModel)
    {
        Vec3 p{}, f{}, r{}, u{};
        if (readVec(g_camModel + OFF_CAM_POS, &p) && readVec(g_camModel + OFF_CAM_FWD, &f) &&
            readVec(g_camModel + OFF_CAM_RIGHT, &r) && readVec(g_camModel + OFF_CAM_UP, &u))
        {
            const float l = sqrtf(f.x * f.x + f.y * f.y + f.z * f.z);
            if (l > 0.9f && l < 1.1f)
            {
                g_camPos = p;
                g_camFwd = { f.x / l, f.y / l, f.z / l };
                g_camRight = r; g_camUp = u;
                g_camDist = read<float>(g_camModel + OFF_CAM_DIST);
                g_camOk = true;
            }
            else g_camOk = false;
        }
        else g_camOk = false;
    }
    else g_camOk = false;
}

static bool updaterOk(uintptr_t bu, uintptr_t bem, uintptr_t world)
{
    uintptr_t back = 0;
    if (!readPtr(bu + OFF_UPD_BEM, &back) || back != bem) return false;

    uintptr_t battle = 0;
    if (!readPtr(bu + OFF_UPD_BATTLE, &battle))
        if (!readPtr(bu + OFF_UPD_BATTLE_ALT, &battle)) return false;

    uintptr_t ents = 0, w = 0, cam = 0;
    if (!readPtr(battle + OFF_BATTLE_ENTS, &ents)) return false;
    if (!readPtr(ents + OFF_BEM_WORLD, &w) || w != world) return false;
    if (!readPtr(battle + OFF_BATTLE_CAM, &cam)) return false;
    return validCameraModel(cam);
}

static uintptr_t findUpdater()
{
    if (!g_world) return 0;

    MEMORY_BASIC_INFORMATION m{};
    uintptr_t a = 0x10000;
    size_t budget = 900ull * 1024 * 1024;
    std::vector<uint8_t> buf;

    while (queryRegion(a, &m) && budget)
    {
        const uintptr_t nx = reinterpret_cast<uintptr_t>(m.BaseAddress) + m.RegionSize;
        const bool usable = m.State == MEM_COMMIT && m.Type != MEM_IMAGE &&
                            (m.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) && !(m.Protect & PAGE_GUARD) &&
                            m.RegionSize <= 32ull * 1024 * 1024;

        if (usable)
        {
            buf.resize(m.RegionSize);
            if (readRaw(reinterpret_cast<uintptr_t>(m.BaseAddress), buf.data(), m.RegionSize))
            {
                budget -= (std::min)(budget, static_cast<size_t>(m.RegionSize));
                const uint8_t* p = buf.data();
                const size_t n = buf.size() / sizeof(uintptr_t);
                for (size_t i = 0; i < n; ++i)
                {
                    uintptr_t v = 0;
                    memcpy(&v, p + i * sizeof(uintptr_t), sizeof(v));
                    if (v != g_world) continue;
                    const uintptr_t at = reinterpret_cast<uintptr_t>(m.BaseAddress) + i * sizeof(uintptr_t);
                    if (at < OFF_BEM_WORLD + OFF_UPD_BEM) continue;
                    const uintptr_t bem = at - OFF_BEM_WORLD;
                    const uintptr_t bu = bem - OFF_UPD_BEM;
                    if (updaterOk(bu, bem, g_world)) return bu;
                }
            }
        }
        if (nx <= a) break;
        a = nx;
    }
    return 0;
}

static uintptr_t ensureUpdater()
{
    if (g_updater)
    {
        uintptr_t bem = 0;
        if (readPtr(g_updater + OFF_UPD_BEM, &bem) && bem) return g_updater;
        g_updater = 0;
    }
    if (!g_world) return 0;
    const DWORD now = GetTickCount();
    if (now - g_lastUpdScan < 2000) return 0;
    g_lastUpdScan = now;

    uintptr_t bu = updaterFromPattern();
    if (bu && g_world)
    {
        uintptr_t bem = 0;
        if (readPtr(bu + OFF_UPD_BEM, &bem) && bem && updaterOk(bu, bem, g_world)) { g_updater = bu; return bu; }
        bu = 0;
    }
    bu = findUpdater();
    if (bu) g_updater = bu;
    return bu;
}

// ------------------------------------------------------------------ patch
static void instantLoot(uintptr_t bu)
{
    if (!bu) return;

    uintptr_t battle = 0;
    if (!readPtr(bu + OFF_UPD_BATTLE, &battle)) readPtr(bu + OFF_UPD_BATTLE_ALT, &battle);
    if (!battle) return;

    // loot hold model: BattleModel -> content(+0x540) -> hold(+0x18)
    uintptr_t content = 0;
    if (!readPtr(battle + 0x540, &content)) return;

    uintptr_t hold = 0;
    if (!readPtr(content + 0x18, &hold)) return;

    write<float>(hold + 0x58, 0.0001f);

    uintptr_t dict = 0;
    if (!readPtr(hold + 0x18, &dict)) return;

    auto poke = [](uintptr_t desc) {
        if (!desc) return;
        const float a = read<float>(desc + 0x40);
        const float b = read<float>(desc + 0x68);
        if (!finite(a) || !finite(b)) return;
        write<float>(desc + 0x40, 0.0f);
        write<float>(desc + 0x68, 0.0f);
    };

    uintptr_t entries = 0;
    int count = 0;
    if (dictShape(dict, &entries, &count))
    {
        for (int i = 0; i < (std::min)(count, 500); ++i)
        {
            uintptr_t d = 0;
            if (readPtr(entries + 0x20 + (uintptr_t)i * ENTRY_STRIDE + OFF_ENTRY_VALUE, &d)) poke(d);
        }
        return;
    }

    // list-of-pairs fallback
    uintptr_t items = 0;
    if (!readPtr(dict + OFF_LIST_ITEMS, &items)) return;
    const int size = read<int>(dict + OFF_LIST_SIZE);
    if (size <= 0 || size > 500) return;
    for (int i = 0; i < size; ++i)
    {
        uintptr_t d = 0;
        if (readPtr(items + 0x20 + (uintptr_t)i * ENTRY_STRIDE + OFF_ENTRY_VALUE, &d)) poke(d);
    }
}

// ------------------------------------------------------------------ entities
struct Ent { Vec3 pos; float dist; int hp; bool dead; int type; };

static CRITICAL_SECTION g_snapLock;
static std::vector<Ent> g_snap;
static uintptr_t g_localChar = 0;

static void collectDict(uintptr_t dict, uintptr_t posOff, int type, std::vector<Ent>& out, uintptr_t* localOut)
{
    uintptr_t entries = 0;
    int count = 0;
    if (!dictShape(dict, &entries, &count)) return;

    float bestLocal = 1e9f;
    uintptr_t bestLocalChar = 0;

    const int cap = (std::min)(count, 400);
    for (int i = 0; i < cap; ++i)
    {
        uintptr_t e = 0;
        if (!readPtr(entries + 0x20 + (uintptr_t)i * ENTRY_STRIDE + OFF_ENTRY_VALUE, &e)) continue;

        uintptr_t pm = 0;
        if (!readPtr(e + posOff, &pm)) continue;

        Vec3 p{};
        if (!readVec(pm + OFF_POS_X, &p)) continue;

        const float dx = p.x - g_camPos.x, dy = p.y - g_camPos.y, dz = p.z - g_camPos.z;
        const float dist = sqrtf(dx * dx + dy * dy + dz * dz);

        Ent en{ p, dist, -1, false, type };

        if (type == T_PLAYER)
        {
            // health
            uintptr_t data = 0, priv = 0, hp = 0;
            if (readPtr(e + OFF_CHAR_DATA, &data) && readPtr(data + OFF_DATA_PRIV, &priv) &&
                readPtr(priv + OFF_PRIV_HEALTH, &hp))
            {
                const int h = read<int>(hp + OFF_POS_X);
                if (h >= 0 && h <= 100000) en.hp = h;
            }
            uintptr_t dm = 0;
            if (readPtr(e + OFF_CHAR_DEAD, &dm)) en.dead = read<uint8_t>(dm + OFF_POS_X) != 0;

            // local player = nearest to the follow point
            const float fd = (g_camDist > 0.5f && g_camDist < 25.0f) ? g_camDist : 4.0f;
            const Vec3 aim{ g_camPos.x + g_camFwd.x * fd,
                            g_camPos.y + g_camFwd.y * fd,
                            g_camPos.z + g_camFwd.z * fd };
            const float lx = p.x - aim.x, ly = p.y - aim.y, lz = p.z - aim.z;
            const float ls = lx * lx + ly * ly + lz * lz;
            if (ls < bestLocal) { bestLocal = ls; bestLocalChar = e; }

            if (dist > (float)cfg.maxDist) continue;
            if (dist < 0.8f) continue;
        }
        else if (dist > (float)cfg.maxDist) continue;

        out.push_back(en);
    }

    if (localOut && bestLocalChar) *localOut = bestLocalChar;
}

static void snapshotEntities()
{
    std::vector<Ent> out;
    uintptr_t local = 0;

    if (g_world && g_camOk)
    {
        uintptr_t d = 0;
        if (cfg.drawPlayers && readPtr(g_world + OFF_WEM_CHARS, &d))
            collectDict(d, OFF_CHAR_TRANSFORM, T_PLAYER, out, &local);
        if (cfg.drawContainers && readPtr(g_world + OFF_WEM_CONTAINERS, &d))
            collectDict(d, OFF_CONTAINER_POS, T_CONTAINER, out, nullptr);
        if (cfg.drawLoot && readPtr(g_world + OFF_WEM_LOOTS, &d))
            collectDict(d, OFF_LOOT_POS, T_LOOT, out, nullptr);
        if (cfg.drawLoot && readPtr(g_world + OFF_WEM_VLOOTS, &d))
            collectDict(d, OFF_VLOOT_POS, T_VLOOT, out, nullptr);
        if (cfg.drawDoors && readPtr(g_world + OFF_WEM_DOORS, &d))
            collectDict(d, OFF_DOOR_POS, T_DOOR, out, nullptr);
    }

    std::sort(out.begin(), out.end(), [](const Ent& a, const Ent& b) { return a.dist < b.dist; });
    if (out.size() > 400) out.resize(400);

    EnterCriticalSection(&g_snapLock);
    g_snap.swap(out);
    g_localChar = local;
    LeaveCriticalSection(&g_snapLock);
}

// ------------------------------------------------------------------ w2s / aim
static bool w2s(const Vec3& p, float w, float h, float fovDeg, float* sx, float* sy)
{
    if (!g_camOk) return false;
    const Vec3 d{ p.x - g_camPos.x, p.y - g_camPos.y, p.z - g_camPos.z };
    const float z = d.x * g_camFwd.x + d.y * g_camFwd.y + d.z * g_camFwd.z;
    if (z < 0.1f) return false;

    const float x = d.x * g_camRight.x + d.y * g_camRight.y + d.z * g_camRight.z;
    const float y = d.x * g_camUp.x + d.y * g_camUp.y + d.z * g_camUp.z;

    const float focal = 1.0f / tanf(fovDeg * 0.5f * 3.14159265f / 180.0f);
    const float aspect = (h > 1.0f) ? (w / h) : 1.0f;

    *sx = ((x / z) * focal / aspect * 0.5f + 0.5f) * w;
    *sy = (0.5f - (y / z) * focal * 0.5f) * h;
    return true;
}

static void doAim()
{
    if (!g_camOk || !g_gameWnd) return;
    if (GetForegroundWindow() != g_gameWnd) return;

    RECT rc{};
    if (!GetClientRect(g_gameWnd, &rc)) return;
    const float w = (float)(rc.right - rc.left), h = (float)(rc.bottom - rc.top);
    if (w < 32 || h < 32) return;

    const float cx = w * 0.5f, cy = h * 0.5f;
    const float fov = (float)cfg.aimFov;

    EnterCriticalSection(&g_snapLock);
    std::vector<Ent> local = g_snap;
    const uintptr_t self = g_localChar;
    LeaveCriticalSection(&g_snapLock);

    float best = 1e9f, bx = 0, by = 0;
    bool found = false;

    for (const Ent& e : local)
    {
        if (e.type != T_PLAYER || e.dead) continue;
        if (e.hp == 0) continue;

        Vec3 head = e.pos;
        head.y += cfg.heightX10 * 0.085f;

        float sx = 0, sy = 0;
        if (!w2s(head, w, h, (float)cfg.espFov, &sx, &sy)) continue;

        const float dx = sx - cx, dy = sy - cy;
        const float d = sqrtf(dx * dx + dy * dy);
        if (d > fov || d >= best) continue;
        best = d; bx = dx; by = dy; found = true;
    }
    (void)self;

    if (!found || best < 1.5f) return;

    const float k = (float)cfg.smooth / 100.0f;
    int mx = (int)(bx * k), my = (int)(by * k);
    if (!mx && !my) return;

    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dx = mx; in.mi.dy = my; in.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &in, sizeof(in));
}

// ==================================================================
//  gui / overlay
// ==================================================================
static CRITICAL_SECTION g_logLock;
static std::deque<std::wstring> g_logQ;
static std::wstring g_status;

static HWND g_gui = nullptr, g_overlay = nullptr, g_gameWnd = nullptr;
static HHOOK g_kbHook = nullptr, g_msHook = nullptr;
static std::atomic<int>  g_capture{ 0 };
static std::atomic<bool> g_hold{ false };

static void logf(const wchar_t* fmt, ...)
{
    wchar_t b[1024]{};
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(b, _countof(b), _TRUNCATE, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_logLock);
    g_logQ.push_back(b);
    while (g_logQ.size() > 200) g_logQ.pop_front();
    LeaveCriticalSection(&g_logLock);
}

static void setStatus(const std::wstring& s)
{
    EnterCriticalSection(&g_snapLock);
    g_status = s;
    LeaveCriticalSection(&g_snapLock);
}

static bool aimActive() { return cfg.aim && (cfg.aimHoldMode ? g_hold.load() : true); }

// ------------------------------------------------------------------ config io
static void configPath(wchar_t* out)
{
    GetModuleFileNameW(nullptr, out, MAX_PATH);
    wchar_t* d = wcsrchr(out, L'.');
    if (d) wcscpy_s(d, MAX_PATH - (size_t)(d - out), L".ini");
    else   wcscat_s(out, MAX_PATH, L".ini");
}

static int  iniGet(const wchar_t* p, const wchar_t* k, int d) { return (int)GetPrivateProfileIntW(L"s", k, d, p); }
static void iniPut(const wchar_t* p, const wchar_t* k, int v)
{
    wchar_t b[32]{}; _snwprintf_s(b, _countof(b), _TRUNCATE, L"%d", v);
    WritePrivateProfileStringW(L"s", k, b, p);
}

static void saveConfig()
{
    wchar_t p[MAX_PATH]{}; configPath(p);
    iniPut(p, L"esp", cfg.esp); iniPut(p, L"aim", cfg.aim); iniPut(p, L"loot", cfg.instantLoot);
    iniPut(p, L"hold", cfg.aimHoldMode); iniPut(p, L"box", cfg.drawBox); iniPut(p, L"dist", cfg.drawDist);
    iniPut(p, L"hp", cfg.drawHealth); iniPut(p, L"snap", cfg.drawSnapline);
    iniPut(p, L"players", cfg.drawPlayers); iniPut(p, L"cont", cfg.drawContainers);
    iniPut(p, L"lootents", cfg.drawLoot); iniPut(p, L"doors", cfg.drawDoors);
    iniPut(p, L"afov", cfg.aimFov); iniPut(p, L"smooth", cfg.smooth);
    iniPut(p, L"efov", cfg.espFov); iniPut(p, L"maxdist", cfg.maxDist);
    iniPut(p, L"mkey", cfg.menuKey); iniPut(p, L"ekey", cfg.espKey);
    iniPut(p, L"akey", cfg.aimKey); iniPut(p, L"hkey", cfg.holdKey);
    iniPut(p, L"height", cfg.heightX10);
}

static void loadConfig()
{
    wchar_t p[MAX_PATH]{}; configPath(p);
    cfg.esp = iniGet(p, L"esp", cfg.esp) != 0;
    cfg.aim = iniGet(p, L"aim", cfg.aim) != 0;
    cfg.instantLoot = iniGet(p, L"loot", cfg.instantLoot) != 0;
    cfg.aimHoldMode = iniGet(p, L"hold", cfg.aimHoldMode) != 0;
    cfg.drawBox = iniGet(p, L"box", cfg.drawBox) != 0;
    cfg.drawDist = iniGet(p, L"dist", cfg.drawDist) != 0;
    cfg.drawHealth = iniGet(p, L"hp", cfg.drawHealth) != 0;
    cfg.drawSnapline = iniGet(p, L"snap", cfg.drawSnapline) != 0;
    cfg.drawPlayers = iniGet(p, L"players", cfg.drawPlayers) != 0;
    cfg.drawContainers = iniGet(p, L"cont", cfg.drawContainers) != 0;
    cfg.drawLoot = iniGet(p, L"lootents", cfg.drawLoot) != 0;
    cfg.drawDoors = iniGet(p, L"doors", cfg.drawDoors) != 0;
    cfg.aimFov = iniGet(p, L"afov", cfg.aimFov);
    cfg.smooth = iniGet(p, L"smooth", cfg.smooth);
    cfg.espFov = iniGet(p, L"efov", cfg.espFov);
    cfg.maxDist = iniGet(p, L"maxdist", cfg.maxDist);
    cfg.menuKey = iniGet(p, L"mkey", cfg.menuKey);
    cfg.espKey = iniGet(p, L"ekey", cfg.espKey);
    cfg.aimKey = iniGet(p, L"akey", cfg.aimKey);
    cfg.holdKey = iniGet(p, L"hkey", cfg.holdKey);
    cfg.heightX10 = iniGet(p, L"height", cfg.heightX10);

    if (cfg.smooth < 1) cfg.smooth = 1;
    if (cfg.smooth > 100) cfg.smooth = 100;
    if (cfg.aimFov < 10) cfg.aimFov = 10;
    if (cfg.aimFov > 600) cfg.aimFov = 600;
    if (cfg.espFov < 30) cfg.espFov = 30;
    if (cfg.espFov > 120) cfg.espFov = 120;
    if (cfg.maxDist < 10) cfg.maxDist = 10;
    if (cfg.heightX10 < 1) cfg.heightX10 = 18;
}

static std::wstring keyName(int vk)
{
    switch (vk)
    {
    case VK_LBUTTON: return L"LMB";   case VK_RBUTTON: return L"RMB";
    case VK_MBUTTON: return L"MMB";   case VK_XBUTTON1: return L"MB4";
    case VK_XBUTTON2: return L"MB5";  case VK_LSHIFT: return L"LSHIFT";
    case VK_RSHIFT: return L"RSHIFT"; case VK_LCONTROL: return L"LCTRL";
    case VK_RCONTROL: return L"RCTRL"; case VK_LMENU: return L"LALT";
    case VK_RMENU: return L"RALT";    case VK_SPACE: return L"SPACE";
    case VK_TAB: return L"TAB";       case VK_INSERT: return L"INS";
    case VK_DELETE: return L"DEL";    case VK_HOME: return L"HOME";
    case VK_END: return L"END";       case VK_PRIOR: return L"PGUP";
    case VK_NEXT: return L"PGDN";     case VK_UP: return L"UP";
    case VK_DOWN: return L"DOWN";     case VK_LEFT: return L"LEFT";
    case VK_RIGHT: return L"RIGHT";   case 0: return L"NONE";
    }
    wchar_t b[16]{};
    if (vk >= VK_F1 && vk <= VK_F24) { _snwprintf_s(b, _countof(b), _TRUNCATE, L"F%d", vk - VK_F1 + 1); return b; }
    if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z')) { b[0] = (wchar_t)vk; return b; }
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"0x%02X", vk);
    return b;
}

static HWND findGameWindow(DWORD pid)
{
    struct C { DWORD pid; HWND best; long area; } c{ pid, nullptr, 0 };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<C*>(lp);
        DWORD p = 0; GetWindowThreadProcessId(h, &p);
        if (p != c->pid || !IsWindowVisible(h)) return TRUE;
        RECT r{};
        if (!GetClientRect(h, &r)) return TRUE;
        const long a = (r.right - r.left) * (r.bottom - r.top);
        if (a > c->area) { c->area = a; c->best = h; }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&c));
    return c.best;
}

// ------------------------------------------------------------------ overlay
static void positionOverlay()
{
    if (!g_overlay) return;
    if (!cfg.esp || !g_gameWnd || !IsWindow(g_gameWnd) || GetForegroundWindow() != g_gameWnd)
    { ShowWindow(g_overlay, SW_HIDE); return; }

    RECT r{}; POINT tl{ 0, 0 };
    if (!GetClientRect(g_gameWnd, &r)) { ShowWindow(g_overlay, SW_HIDE); return; }
    ClientToScreen(g_gameWnd, &tl);
    const int w = r.right - r.left, h = r.bottom - r.top;
    if (w <= 0 || h <= 0) { ShowWindow(g_overlay, SW_HIDE); return; }
    SetWindowPos(g_overlay, HWND_TOPMOST, tl.x, tl.y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

static void drawEsp(HDC dc, int w, int h)
{
    EnterCriticalSection(&g_snapLock);
    std::vector<Ent> list = g_snap;
    const uintptr_t self = g_localChar;
    const bool cam = g_camOk;
    LeaveCriticalSection(&g_snapLock);
    if (!cam) return;

    HPEN pPlayer = CreatePen(PS_SOLID, 1, RGB(235, 70, 70));
    HPEN pCont   = CreatePen(PS_SOLID, 1, RGB(240, 200, 60));
    HPEN pLoot   = CreatePen(PS_SOLID, 1, RGB(90, 220, 90));
    HPEN pVeh    = CreatePen(PS_SOLID, 1, RGB(200, 130, 240));
    HPEN pDoor   = CreatePen(PS_SOLID, 1, RGB(80, 200, 240));
    HPEN pSnap   = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
    HGDIOBJ oldPen = SelectObject(dc, pPlayer);
    HGDIOBJ oldBr = SelectObject(dc, GetStockObject(NULL_BRUSH));

    HFONT f = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HGDIOBJ oldFont = SelectObject(dc, f);
    SetBkMode(dc, TRANSPARENT);

    const float fw = (float)w, fh = (float)h;

    for (const Ent& e : list)
    {
        const float height = (e.type == T_PLAYER) ? (cfg.heightX10 * 0.1f) : (e.type == T_DOOR ? 1.9f : 0.6f);

        Vec3 head = e.pos; head.y += height;

        float x1 = 0, y1 = 0, x2 = 0, y2 = 0;
        if (!w2s(e.pos, fw, fh, (float)cfg.espFov, &x1, &y1)) continue;
        if (!w2s(head, fw, fh, (float)cfg.espFov, &x2, &y2)) continue;

        float bh = y1 - y2;
        if (bh < 3.0f) bh = 3.0f;
        if (bh > fh) bh = fh;
        const float bw = bh * 0.45f;

        const int l = (int)(x1 - bw * 0.5f), t = (int)y2, r = (int)(x1 + bw * 0.5f), b = (int)(y2 + bh);
        if (r < 0 || l > w || b < 0 || t > h) continue;

        COLORREF col = RGB(235, 70, 70);
        HPEN pen = pPlayer;
        switch (e.type)
        {
        case T_CONTAINER: col = RGB(240, 200, 60); pen = pCont; break;
        case T_LOOT:      col = RGB(90, 220, 90);  pen = pLoot; break;
        case T_VLOOT:     col = RGB(200, 130, 240); pen = pVeh; break;
        case T_DOOR:      col = RGB(80, 200, 240); pen = pDoor; break;
        }

        if (cfg.drawBox)
        {
            SelectObject(dc, pen);
            Rectangle(dc, l, t, r, b);
        }

        if (cfg.drawSnapline)
        {
            SelectObject(dc, pSnap);
            MoveToEx(dc, (int)(fw * 0.5f), h - 1, nullptr);
            LineTo(dc, (int)x1, b);
        }

        if (e.type == T_PLAYER && cfg.drawHealth && e.hp >= 0)
        {
            const int barH = b - t;
            const int hpw = (std::min)(e.hp, 100) * barH / 100;
            HBRUSH g = CreateSolidBrush(RGB(70, 200, 70));
            RECT br{ l - 5, b - hpw, l - 2, b };
            FillRect(dc, &br, g);
            DeleteObject(g);
        }

        if (cfg.drawDist)
        {
            wchar_t lbl[48]{};
            if (e.type == T_PLAYER && e.hp >= 0)
                _snwprintf_s(lbl, _countof(lbl), _TRUNCATE, L"%dm %d", (int)(e.dist + 0.5f), e.hp);
            else
                _snwprintf_s(lbl, _countof(lbl), _TRUNCATE, L"%dm", (int)(e.dist + 0.5f));
            SetTextColor(dc, col);
            TextOutW(dc, l, t - 15, lbl, (int)wcslen(lbl));
        }
    }
    (void)self;

    if (cfg.aim && aimActive() && cfg.aimHoldMode)
    {
        HPEN fp = CreatePen(PS_DOT, 1, RGB(120, 255, 120));
        SelectObject(dc, fp);
        Ellipse(dc, (int)(fw * 0.5f - cfg.aimFov), (int)(fh * 0.5f - cfg.aimFov),
                    (int)(fw * 0.5f + cfg.aimFov), (int)(fh * 0.5f + cfg.aimFov));
        DeleteObject(fp);
    }

    SelectObject(dc, oldFont);
    SelectObject(dc, oldBr);
    SelectObject(dc, oldPen);
    DeleteObject(f);
    DeleteObject(pPlayer); DeleteObject(pCont); DeleteObject(pLoot);
    DeleteObject(pVeh); DeleteObject(pDoor); DeleteObject(pSnap);
}

static void renderOverlay()
{
    if (!g_overlay || !IsWindowVisible(g_overlay)) return;
    RECT r{};
    if (!GetClientRect(g_overlay, &r)) return;
    const int w = r.right, h = r.bottom;
    if (w <= 0 || h <= 0) return;

    HDC dc = GetDC(g_overlay);
    if (!dc) return;
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    HGDIOBJ ob = SelectObject(mem, bmp);

    HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(mem, &r, bg);
    DeleteObject(bg);

    drawEsp(mem, w, h);
    BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);

    SelectObject(mem, ob);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(g_overlay, dc);
}

static LRESULT CALLBACK OverlayProc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_TIMER) { positionOverlay(); renderOverlay(); return 0; }
    if (m == WM_PAINT)
    {
        PAINTSTRUCT ps{};
        BeginPaint(h, &ps); EndPaint(h, &ps);
        renderOverlay();
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

static void createOverlay()
{
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = OverlayProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"ilOverlayWnd";
    RegisterClassExW(&wc);
    g_overlay = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST |
                                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
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

enum
{
    IDC_ESP = 1001, IDC_AIM, IDC_LOOT, IDC_TMODE, IDC_BOX, IDC_DIST, IDC_HP,
    IDC_SNAP, IDC_PLAYERS, IDC_CONTAINERS, IDC_LOOTENTS, IDC_DOORS,
    IDC_AFOV, IDC_SMOOTH, IDC_EFOV, IDC_MAXDIST,
    IDC_KMENU, IDC_KESP, IDC_KAIM, IDC_KHOLD,
    IDC_SAVE, IDC_REATTACH, IDC_STATUS, IDC_LOG,
};

static HWND g_hStatus = nullptr, g_hLog = nullptr;

static void setCheck(HWND p, int id, bool v)
{
    if (HWND h = GetDlgItem(p, id)) SendMessageW(h, BM_SETCHECK, v ? BST_CHECKED : BST_UNCHECKED, 0);
}

static void syncControls(HWND h)
{
    setCheck(h, IDC_ESP, cfg.esp); setCheck(h, IDC_AIM, cfg.aim);
    setCheck(h, IDC_LOOT, cfg.instantLoot); setCheck(h, IDC_TMODE, cfg.aimHoldMode);
    setCheck(h, IDC_BOX, cfg.drawBox); setCheck(h, IDC_DIST, cfg.drawDist);
    setCheck(h, IDC_HP, cfg.drawHealth); setCheck(h, IDC_SNAP, cfg.drawSnapline);
    setCheck(h, IDC_PLAYERS, cfg.drawPlayers); setCheck(h, IDC_CONTAINERS, cfg.drawContainers);
    setCheck(h, IDC_LOOTENTS, cfg.drawLoot); setCheck(h, IDC_DOORS, cfg.drawDoors);

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
}

static LRESULT CALLBACK GuiProc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m)
    {
    case WM_CREATE:
    {
        HINSTANCE in = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(h, GWLP_HINSTANCE));
        HFONT f = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        auto mk = [&](const wchar_t* c, const wchar_t* t, DWORD s, int x, int y, int w, int hh, int id) {
            HWND o = CreateWindowExW(0, c, t, WS_CHILD | WS_VISIBLE | s, x, y, w, hh, h,
                                     reinterpret_cast<HMENU>((INT_PTR)id), in, nullptr);
            if (o && f) SendMessageW(o, WM_SETFONT, (WPARAM)f, TRUE);
            return o;
        };
        int y = 8;
        mk(L"BUTTON", L"ESP [toggle]", BS_AUTOCHECKBOX, 10, y, 170, 22, IDC_ESP);
        mk(L"BUTTON", L"Aimbot [toggle]", BS_AUTOCHECKBOX, 190, y, 170, 22, IDC_AIM); y += 26;
        mk(L"BUTTON", L"Instant loot", BS_AUTOCHECKBOX, 10, y, 170, 22, IDC_LOOT);
        mk(L"BUTTON", L"Aim: hold key", BS_AUTOCHECKBOX, 190, y, 170, 22, IDC_TMODE); y += 28;

        mk(L"STATIC", L"ESP elements", 0, 10, y, 200, 18, -1); y += 20;
        mk(L"BUTTON", L"Boxes", BS_AUTOCHECKBOX, 10, y, 80, 22, IDC_BOX);
        mk(L"BUTTON", L"Distance", BS_AUTOCHECKBOX, 95, y, 85, 22, IDC_DIST);
        mk(L"BUTTON", L"Health", BS_AUTOCHECKBOX, 185, y, 80, 22, IDC_HP); y += 24;
        mk(L"BUTTON", L"Snaplines", BS_AUTOCHECKBOX, 10, y, 95, 22, IDC_SNAP); y += 24;
        mk(L"BUTTON", L"Players", BS_AUTOCHECKBOX, 10, y, 80, 22, IDC_PLAYERS);
        mk(L"BUTTON", L"Containers", BS_AUTOCHECKBOX, 95, y, 95, 22, IDC_CONTAINERS); y += 24;
        mk(L"BUTTON", L"Loot", BS_AUTOCHECKBOX, 10, y, 80, 22, IDC_LOOTENTS);
        mk(L"BUTTON", L"Doors", BS_AUTOCHECKBOX, 95, y, 80, 22, IDC_DOORS); y += 30;

        mk(L"STATIC", L"Aim FOV (px)", 0, 10, y, 180, 18, -1);
        mk(L"STATIC", L"Smoothing", 0, 200, y, 160, 18, -1); y += 18;
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 10, y, 180, 24, IDC_AFOV);
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 200, y, 170, 24, IDC_SMOOTH); y += 30;
        SendDlgItemMessageW(h, IDC_AFOV, TBM_SETRANGE, TRUE, MAKELPARAM(10, 600));
        SendDlgItemMessageW(h, IDC_SMOOTH, TBM_SETRANGE, TRUE, MAKELPARAM(1, 100));

        mk(L"STATIC", L"Camera FOV (tune to game)", 0, 10, y, 200, 18, -1);
        mk(L"STATIC", L"Max distance", 0, 210, y, 150, 18, -1); y += 18;
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 10, y, 190, 24, IDC_EFOV);
        mk(L"msctls_trackbar32", L"", TBS_HORZ | TBS_NOTICKS, 210, y, 160, 24, IDC_MAXDIST); y += 30;
        SendDlgItemMessageW(h, IDC_EFOV, TBM_SETRANGE, TRUE, MAKELPARAM(30, 120));
        SendDlgItemMessageW(h, IDC_MAXDIST, TBM_SETRANGE, TRUE, MAKELPARAM(10, 500));

        mk(L"STATIC", L"Keybinds", 0, 10, y, 200, 18, -1); y += 20;
        mk(L"BUTTON", L"Menu key", BS_PUSHBUTTON, 10, y, 110, 24, IDC_KMENU);
        mk(L"BUTTON", L"ESP key", BS_PUSHBUTTON, 130, y, 110, 24, IDC_KESP);
        mk(L"BUTTON", L"Aimbot key", BS_PUSHBUTTON, 250, y, 120, 24, IDC_KAIM); y += 28;
        mk(L"BUTTON", L"Aim hold key", BS_PUSHBUTTON, 10, y, 110, 24, IDC_KHOLD);
        mk(L"BUTTON", L"Save", BS_PUSHBUTTON, 130, y, 110, 24, IDC_SAVE);
        mk(L"BUTTON", L"Reattach", BS_PUSHBUTTON, 250, y, 120, 24, IDC_REATTACH); y += 32;

        g_hStatus = mk(L"STATIC", L"starting...", 0, 10, y, 360, 40, IDC_STATUS); y += 44;
        g_hLog = mk(L"LISTBOX", L"", WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT, 10, y, 360, 110, IDC_LOG);
        syncControls(h);
        return 0;
    }
    case WM_HSCROLL:
    {
        HWND s = reinterpret_cast<HWND>(lp);
        const int id = GetDlgCtrlID(s);
        const int p = (int)SendMessageW(s, TBM_GETPOS, 0, 0);
        if (id == IDC_AFOV) cfg.aimFov = p;
        if (id == IDC_SMOOTH) cfg.smooth = p;
        if (id == IDC_EFOV) cfg.espFov = p;
        if (id == IDC_MAXDIST) cfg.maxDist = p;
        return 0;
    }
    case WM_COMMAND:
    {
        const int id = LOWORD(wp);
        if (HIWORD(wp) != BN_CLICKED) return 0;
        switch (id)
        {
        case IDC_ESP: cfg.esp = IsDlgButtonChecked(h, IDC_ESP) == BST_CHECKED; return 0;
        case IDC_AIM: cfg.aim = IsDlgButtonChecked(h, IDC_AIM) == BST_CHECKED; return 0;
        case IDC_LOOT: cfg.instantLoot = IsDlgButtonChecked(h, IDC_LOOT) == BST_CHECKED; return 0;
        case IDC_BOX: cfg.drawBox = IsDlgButtonChecked(h, IDC_BOX) == BST_CHECKED; return 0;
        case IDC_DIST: cfg.drawDist = IsDlgButtonChecked(h, IDC_DIST) == BST_CHECKED; return 0;
        case IDC_HP: cfg.drawHealth = IsDlgButtonChecked(h, IDC_HP) == BST_CHECKED; return 0;
        case IDC_SNAP: cfg.drawSnapline = IsDlgButtonChecked(h, IDC_SNAP) == BST_CHECKED; return 0;
        case IDC_PLAYERS: cfg.drawPlayers = IsDlgButtonChecked(h, IDC_PLAYERS) == BST_CHECKED; return 0;
        case IDC_CONTAINERS: cfg.drawContainers = IsDlgButtonChecked(h, IDC_CONTAINERS) == BST_CHECKED; return 0;
        case IDC_LOOTENTS: cfg.drawLoot = IsDlgButtonChecked(h, IDC_LOOTENTS) == BST_CHECKED; return 0;
        case IDC_DOORS: cfg.drawDoors = IsDlgButtonChecked(h, IDC_DOORS) == BST_CHECKED; return 0;
        case IDC_TMODE: cfg.aimHoldMode = IsDlgButtonChecked(h, IDC_TMODE) == BST_CHECKED; return 0;
        case IDC_KMENU: g_capture = 1; SetDlgItemTextW(h, IDC_KMENU, L"Menu key: ..."); return 0;
        case IDC_KESP:  g_capture = 2; SetDlgItemTextW(h, IDC_KESP, L"ESP key: ..."); return 0;
        case IDC_KAIM:  g_capture = 3; SetDlgItemTextW(h, IDC_KAIM, L"Aimbot key: ..."); return 0;
        case IDC_KHOLD: g_capture = 4; SetDlgItemTextW(h, IDC_KHOLD, L"Aim hold key: ..."); return 0;
        case IDC_SAVE: saveConfig(); logf(L"config saved"); return 0;
        case IDC_REATTACH:
            g_camModel = g_world = g_updater = 0;
            g_lastStatic = 0; g_lastUpdScan = 0;
            logf(L"re-resolving");
            return 0;
        }
        return 0;
    }
    case WM_APP_CAPTURED:
    {
        const int vk = (int)wp;
        const int which = g_capture.exchange(0);
        if (vk == VK_ESCAPE) { syncControls(h); return 0; }
        if (which == 1) cfg.menuKey = vk;
        if (which == 2) cfg.espKey = vk;
        if (which == 3) cfg.aimKey = vk;
        if (which == 4) cfg.holdKey = vk;
        logf(L"bind: %s", keyName(vk).c_str());
        syncControls(h);
        return 0;
    }
    case WM_APP_TOGGLE:
        if (IsWindowVisible(h)) { if (GetForegroundWindow() == h) ShowWindow(h, SW_HIDE); else SetForegroundWindow(h); }
        else { ShowWindow(h, SW_SHOW); SetForegroundWindow(h); }
        return 0;
    case WM_APP_ESP: cfg.esp = !cfg.esp; syncControls(h); return 0;
    case WM_APP_AIM: cfg.aim = !cfg.aim; syncControls(h); return 0;

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
                const int i = (int)SendMessageW(g_hLog, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
                SendMessageW(g_hLog, LB_SETTOPINDEX, (WPARAM)i, 0);
            }
            EnterCriticalSection(&g_logLock);
        }
        LeaveCriticalSection(&g_logLock);
        return 0;
    }
    case WM_CLOSE: ShowWindow(h, SW_HIDE); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
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
                            CW_USEDEFAULT, CW_USEDEFAULT, 400, 720,
                            nullptr, nullptr, wc.hInstance, nullptr);
    if (g_gui) SetTimer(g_gui, 2, 400, nullptr);
}

// ------------------------------------------------------------------ hooks
static bool gameFocused()
{
    const HWND f = GetForegroundWindow();
    if (!f) return false;
    if (f == g_gameWnd) return true;
    return g_gui && (f == g_gui || IsChild(g_gui, f));
}

static void captureKey(int vk)
{
    if (g_capture.load() && g_gui) PostMessageW(g_gui, WM_APP_CAPTURED, (WPARAM)vk, 0);
}

static LRESULT CALLBACK LLKeyboard(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION)
    {
        const auto* k = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        const bool down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        const int vk = (int)k->vkCode;

        if (g_capture.load()) { if (down) captureKey(vk); return 1; }

        if (vk == cfg.holdKey) g_hold = down;

        if (down && gameFocused())
        {
            if (vk == cfg.menuKey) { PostMessageW(g_gui, WM_APP_TOGGLE, 0, 0); return 1; }
            if (vk == cfg.espKey)  { PostMessageW(g_gui, WM_APP_ESP, 0, 0); return 1; }
            if (vk == cfg.aimKey)  { PostMessageW(g_gui, WM_APP_AIM, 0, 0); return 1; }
        }
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

static LRESULT CALLBACK LLMouse(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION)
    {
        const auto* m = reinterpret_cast<MSLLHOOKSTRUCT*>(lp);
        int vk = 0; bool down = false;
        switch (wp)
        {
        case WM_LBUTTONDOWN: down = true; vk = VK_LBUTTON; break;
        case WM_LBUTTONUP: vk = VK_LBUTTON; break;
        case WM_RBUTTONDOWN: down = true; vk = VK_RBUTTON; break;
        case WM_RBUTTONUP: vk = VK_RBUTTON; break;
        case WM_MBUTTONDOWN: down = true; vk = VK_MBUTTON; break;
        case WM_MBUTTONUP: vk = VK_MBUTTON; break;
        case WM_XBUTTONDOWN: down = true; vk = (HIWORD(m->mouseData) == XBUTTON2) ? VK_XBUTTON2 : VK_XBUTTON1; break;
        case WM_XBUTTONUP: vk = (HIWORD(m->mouseData) == XBUTTON2) ? VK_XBUTTON2 : VK_XBUTTON1; break;
        }
        if (!vk) return CallNextHookEx(nullptr, code, wp, lp);
        if (g_capture.load()) { if (down) captureKey(vk); return CallNextHookEx(nullptr, code, wp, lp); }
        if (vk == cfg.holdKey) g_hold = down;
        if (down && gameFocused() && vk == cfg.aimKey) PostMessageW(g_gui, WM_APP_AIM, 0, 0);
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

// ------------------------------------------------------------------ worker
static void workerThread()
{
    int misses = 0;
    while (g_running.load())
    {
        if (!g_proc) { Sleep(200); continue; }

        refreshStatics();

        if (cfg.instantLoot)
        {
            const uintptr_t bu = ensureUpdater();
            if (bu) instantLoot(bu);
        }

        if ((cfg.esp || aimActive()) && g_world && g_camOk) snapshotEntities();
        else
        {
            EnterCriticalSection(&g_snapLock);
            g_snap.clear();
            LeaveCriticalSection(&g_snapLock);
        }

        if (aimActive()) doAim();

        EnterCriticalSection(&g_snapLock);
        const size_t n = g_snap.size();
        const bool cam = g_camOk;
        LeaveCriticalSection(&g_snapLock);

        if (!g_world && ++misses > 12) { logf(L"world entities unresolved"); misses = 0; }

        wchar_t st[320]{};
        _snwprintf_s(st, _countof(st), _TRUNCATE,
                     L"ga %p  cam %s  world %p\nupdater %p  ents %zu  esp %s  aim %s",
                     (void*)g_gaBase, cam ? L"ok" : L"-", (void*)g_world,
                     (void*)g_updater, n, cfg.esp ? L"on" : L"off", aimActive() ? L"on" : L"off");
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
    }
    enableDebugPrivilege();

    bool watch = false, loot = false, diagMode = false, guiMode = true;
    wchar_t nameArg[MAX_PATH] = L"";
    DWORD pidArg = 0;

    for (int i = 1; i < argc; ++i)
    {
        if (!_stricmp(argv[i], "--watch")) { watch = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--loot")) { loot = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--diag")) { diagMode = true; guiMode = false; continue; }
        if (!_stricmp(argv[i], "--gui")) { guiMode = true; continue; }
        if (!_stricmp(argv[i], "--list")) { printList(); system("pause"); return 0; }
        if (!_stricmp(argv[i], "--pid") && i + 1 < argc) { pidArg = (DWORD)strtoul(argv[++i], nullptr, 10); continue; }
        if (!_stricmp(argv[i], "--base") && i + 1 < argc) { g_forcedBase = (uintptr_t)_strtoui64(argv[++i], nullptr, 16); continue; }
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, nameArg, MAX_PATH);
    }

    DWORD pid = 0;
    if (pidArg) { if (!exeNameForPid(pidArg)) { printf("[!] pid %lu not found\n", pidArg); system("pause"); return 1; } pid = pidArg; }
    else if (nameArg[0]) { pid = findPidExact(nameArg); if (pid) wcscpy_s(g_procName, nameArg); else pid = findPidKeyword(nameArg); }
    else pid = findPidKeyword(DEFAULT_KEYWORD);

    if (!pid) { printf("[!] target not found\n\n"); printList(); system("pause"); return 1; }
    if (!g_procName[0] && !exeNameForPid(pid)) { printf("[!] no exe name\n"); system("pause"); return 1; }
    if (!openTarget(pid)) { printf("[!] cannot open pid %lu\n", pid); system("pause"); return 1; }

    loadNt();

    // exe base (diag) + game dir
    {
        wchar_t path[MAX_PATH * 2]{};
        DWORD len = _countof(path);
        if (QueryFullProcessImageNameW(g_proc, 0, path, &len))
        {
            printf("[+] image path: %ls\n", path);
            wcscpy_s(g_gameDir, path);
            wchar_t* s = wcsrchr(g_gameDir, L'\\');
            if (s) *(s + 1) = 0;
        }
        uintptr_t b = 0; size_t sz = 0;
        if (findModule(pid, g_procName, &b, &sz)) { g_base = b; g_size = sz; }
    }

    g_gameWnd = findGameWindow(pid);

    if (diagMode)
    {
        refreshStatics();
        printf("ga base %p size %zx\n", (void*)g_gaBase, g_gaSize);
        printf("camera model %p  world %p\n", (void*)g_camModel, (void*)g_world);
        system("pause");
        return 0;
    }

    if (loot)
    {
        refreshStatics();
        const uintptr_t bu = ensureUpdater();
        printf("[+] updater %p\n", (void*)bu);
        instantLoot(bu);
        system("pause");
        return 0;
    }

    if (!guiMode)
    {
        refreshStatics();
        printf("[+] watch mode\n");
        for (;;)
        {
            refreshStatics();
            const uintptr_t bu = ensureUpdater();
            if (bu) instantLoot(bu);
            Sleep(WATCH_INTERVAL);
        }
    }

    if (!g_gameWnd) printf("[!] no game window found\n");

    createOverlay();
    createGui();
    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, LLKeyboard, GetModuleHandleW(nullptr), 0);
    g_msHook = SetWindowsHookExW(WH_MOUSE_LL, LLMouse, GetModuleHandleW(nullptr), 0);

    std::thread worker(workerThread);

    logf(L"attached to pid %lu", pid);
    logf(L"%s opens this menu", keyName(cfg.menuKey).c_str());
    logf(L"if ESP is empty: toggle ESP, check status line");

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }

    g_running = false;
    worker.detach();
    if (g_kbHook) UnhookWindowsHookEx(g_kbHook);
    if (g_msHook) UnhookWindowsHookEx(g_msHook);
    if (g_proc) CloseHandle(g_proc);
    saveConfig();
    return 0;
}
