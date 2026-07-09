// ZennComp - AVHIRAL PE Static Decompiler Workbench
// Build: Windows 10/11, C++17, Win32 API, Capstone for disassembly.
// Safety: ZennComp never executes the target binary.
//
// Version V16 Unwind-Aware Engine : analyse x64 .pdata, CFG par fonctions, anti-fausse décompilation.
// - Analyse complète configurable et découpage par fonctions x64 via .pdata/unwind.
// - CFG + prémices SSA + heuristiques de types C/C++ + classes/RTTI + exceptions + appels indirects.
// - IAT, thunks, jump tables, imports annotés, call graph inter-sections et index de fonctions.
// - Triage anti-faux-positifs : code packed/chiffré signalé au lieu d'être décompilé en faux C.

#define NOMINMAX
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winnt.h>
#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <eh.h>
#include <richedit.h>
#include <cwchar>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>
#include <mutex>
#include <exception>
#include <stdexcept>
#include <memory>
#include <limits>
#include <queue>

#include "../resources/resource.h"

// Capstone
#include <capstone/capstone.h>

// --------------------------- UI identifiers ---------------------------
#define IDC_BTN_OPEN       1001
#define IDC_BTN_ANALYZE    1002
#define IDC_BTN_DECOMPILE  1003
#define IDC_BTN_STRINGS    1004
#define IDC_BTN_EXPORT     1005
#define IDC_BTN_CLEAR      1006
#define IDC_BTN_QUIT       1007
#define IDC_BTN_BRUTEFORCE 1008
#define IDC_BTN_UNPACK     1009
#define IDC_BTN_RECOMPILE  1010
#define IDC_BTN_CONVERT    1011
#define IDC_BTN_DECRYPTOR  1012
#define IDC_BTN_XDR        1013
#define IDC_BTN_RUN        1014
#define IDC_BTN_DUMP       1015
#define IDC_BTN_LOAD_DUMP  1016
#define IDC_BTN_SELECT_PROC   1017
#define IDC_BTN_DUMPLIVE      1018

#define IDM_FILE_OPEN_PE          1101
#define IDM_FILE_OPEN_DECOMP_C    1102
#define IDM_FILE_OPEN_OUTPUT_DIR  1103
#define IDM_FILE_EXPORT_REPORT    1104
#define IDM_FILE_EXIT             1105
#define IDM_TOOLS_RECOMPILE_DIR   1110
#define IDM_TOOLS_BRUTEFORCE      1111
#define IDM_TOOLS_DECOMPILE       1112
#define IDM_TOOLS_CONVERT_DIR     1113
#define IDM_TOOLS_DECRYPTOR       1114
#define IDM_TOOLS_XDR             1115
#define IDM_TOOLS_GEN_SCRIPT      1116
#define IDM_HELP_ETHICS           1201

#define IDC_EDITOR_TEXT     4001
#define IDC_EDITOR_SAVE     4002
#define IDC_EDITOR_RECOMPILE 4003
#define IDC_EDITOR_CONVERT   4004
#define IDC_EDITOR_HILITE    4005
#define IDC_EDITOR_PLUS      4006
#define IDC_EDITOR_MINUS     4007

#define WM_ZC_EDITOR_LOADED        (WM_APP + 41)
#define WM_ZC_EDITOR_HILITE_READY  (WM_APP + 42)
#define IDT_EDITOR_HILITE          5301

#define IDC_LOG            2001
#define IDC_STATUS         2002
#define IDC_HEADER         2003
#define IDC_ICONBOX        2004

#define IDC_PROGRESS       3001
#define IDC_PROGRESS_TEXT  3002

static HINSTANCE g_hInst = nullptr;
static HWND g_hWnd = nullptr;
static HWND g_hLog = nullptr;
static HWND g_hStatus = nullptr;
static HWND g_hHeader = nullptr;
static HWND g_hIconBox = nullptr;
static std::wstring g_targetPath;
static std::vector<uint8_t> g_file;
static std::wstring g_lastReport;
static std::wstring g_lastOutputDir;

// Gestion du processus pour dump mémoire
static HANDLE g_hProcess = NULL;
static DWORD g_dwProcessId = 0;
static HANDLE g_hThread = NULL;
static uint64_t g_imageBase = 0;
static uint32_t g_imageSize = 0; // taille de l'image PE (VirtualSize de la dernière section)

static HWND g_hProgressWnd = nullptr;
static HWND g_hProgressBar = nullptr;
static HWND g_hProgressText = nullptr;
static bool g_analysisRunning = false;
static std::mutex g_logMutex;
static std::mutex g_progressMutex;
static HMODULE g_hRichEdit = nullptr;

static bool g_dumpLiveRunning = false;
static HANDLE g_hDumpThread = nullptr;
static std::mutex g_dumpMutex;

// Traducteur SEH -> C++
static void SeTranslator(unsigned int code, EXCEPTION_POINTERS* ep) {
    throw std::runtime_error("SEH exception");
}

// --------------------------- Helpers ---------------------------
static std::wstring Hex64(uint64_t v, int width = 0) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << std::setw(width) << std::setfill(L'0') << v;
    return ss.str();
}

static std::wstring Dec(uint64_t v) {
    std::wstringstream ss;
    ss << std::dec << v;
    return ss.str();
}

static bool ShowBaseSizeDialog(HWND hwndOwner, uint64_t& base, uint32_t& size);

static std::wstring BaseName(const std::wstring& p) {
    size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? p : p.substr(pos + 1);
}

static void SetStatus(const std::wstring& s) {
    if (g_hStatus) SetWindowTextW(g_hStatus, s.c_str());
}

static void AppendLog(const std::wstring& s) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_hLog) return;
    std::wstring text = s;
    if (text.size() < 2 || text.substr(text.size() - 2) != L"\r\n") text += L"\r\n";
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void ClearLog() {
    if (g_hLog) SetWindowTextW(g_hLog, L"");
    g_lastReport.clear();
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) len = MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)len, L'\0');
    if (len > 0) {
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), &out[0], len)) {
            MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), &out[0], len);
        }
    }
    return out;
}

static std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], len, nullptr, nullptr);
    return out;
}

static std::wstring NormalizeTextForWin32Edit(std::wstring text) {
    std::wstring out;
    out.reserve(text.size() + 128);
    for (size_t i = 0; i < text.size(); ++i) {
        wchar_t c = text[i];
        if (c == L'\r') {
            if (i + 1 < text.size() && text[i + 1] == L'\n') { out += L"\r\n"; ++i; }
            else out += L"\r\n";
        } else if (c == L'\n') out += L"\r\n";
        else out += c;
    }
    return out;
}

static std::wstring NormalizeTextForFile(std::wstring text) {
    return NormalizeTextForWin32Edit(text);
}

static bool GetProcessImageBase(HANDLE hProcess, uint64_t& base, uint32_t& size) {
    if (!hProcess) return false;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return false;
    if (cbNeeded == 0) return false;
    // Le premier module est généralement l’exécutable principal
    MODULEINFO mi;
    if (!GetModuleInformation(hProcess, hMods[0], &mi, sizeof(mi)))
        return false;
    base = (uint64_t)mi.lpBaseOfDll;
    size = mi.SizeOfImage;
    return true;
}

static bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out, std::wstring& err) {
    out.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"Impossible d'ouvrir le fichier. Code Win32=" + Dec(GetLastError());
        return false;
    }

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li)) {
        CloseHandle(h);
        err = L"Impossible de lire la taille du fichier.";
        return false;
    }
    if (li.QuadPart <= 0) {
        CloseHandle(h);
        err = L"Taille non supportee pour cette version MVP (>512 Mo ou fichier vide).";
        return false;
    }

    out.resize((size_t)li.QuadPart);
    DWORD total = 0;
    while (total < out.size()) {
        DWORD chunk = (DWORD)std::min<size_t>(out.size() - total, 16 * 1024 * 1024);
        DWORD got = 0;
        if (!ReadFile(h, out.data() + total, chunk, &got, nullptr) || got == 0) {
            CloseHandle(h);
            err = L"Erreur de lecture fichier. Code Win32=" + Dec(GetLastError());
            return false;
        }
        total += got;
    }
    CloseHandle(h);
    return true;
}

static uint64_t Fnv1a64(const std::vector<uint8_t>& data) {
    uint64_t h = 1469598103934665603ull;
    for (uint8_t b : data) {
        h ^= b;
        h *= 1099511628211ull;
    }
    return h;
}

static double Entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint64_t freq[256]{};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double e = 0.0;
    for (uint64_t c : freq) {
        if (!c) continue;
        double p = (double)c / (double)len;
        e -= p * (std::log(p) / std::log(2.0));
    }
    return e;
}

static bool IsPrintableAscii(uint8_t b) {
    return b >= 32 && b <= 126;
}

// --------------------------- Structures PE ---------------------------
struct SectionInfo {
    std::wstring name;
    uint32_t va = 0;
    uint32_t vs = 0;
    uint32_t raw = 0;
    uint32_t rawSize = 0;
    uint32_t characteristics = 0;
};

struct ProcessEntry {
    DWORD pid;
    std::wstring name;
    std::wstring exePath;
};

struct ProcessSelectorData {
    std::vector<ProcessEntry> processes;
    DWORD selectedPid = 0;
};

struct BaseSizeData {
    uint64_t base;
    uint32_t size;
    bool ok;
};

struct ImportEntry {
    std::wstring dll;
    std::wstring name;
    uint16_t ordinal = 0;
    bool byOrdinal = false;
    uint32_t descriptorIndex = 0;
    uint32_t thunkIndex = 0;
    uint32_t lookupRva = 0;      // OriginalFirstThunk ou fallback FirstThunk
    uint32_t iatRva = 0;         // FirstThunk : adresse utilisée au runtime par les call/jmp [IAT]
    uint64_t iatVa = 0;          // ImageBase + iatRva
    uint32_t hintNameRva = 0;
};

struct RuntimeFunctionInfo {
    uint32_t beginRva = 0;
    uint32_t endRva = 0;
    uint32_t unwindRva = 0;
    uint64_t beginVa = 0;
    uint64_t endVa = 0;
};

struct PeInfo {
    bool valid = false;
    bool is64 = false;
    uint16_t machine = 0;
    uint16_t sectionsCount = 0;
    uint32_t timestamp = 0;
    uint64_t imageBase = 0;
    uint32_t entryRva = 0;
    uint32_t subsystem = 0;
    uint32_t importRva = 0;
    uint32_t importSize = 0;
    uint32_t exportRva = 0;
    uint32_t exportSize = 0;
    uint32_t resourceRva = 0;
    uint32_t resourceSize = 0;
    uint32_t exceptionRva = 0;
    uint32_t exceptionSize = 0;
    std::vector<RuntimeFunctionInfo> runtimeFunctions;
    std::vector<SectionInfo> sections;
    std::vector<ImportEntry> imports;
};

// --------------------------- Parser PE ---------------------------
class PeParser {
public:
    explicit PeParser(const std::vector<uint8_t>& bytes) : b(bytes) {}

    bool Parse(PeInfo& info, std::wstring& err) {
        info = PeInfo{};
        if (b.size() < sizeof(IMAGE_DOS_HEADER)) {
            err = L"Fichier trop petit pour contenir un header DOS.";
            return false;
        }
        const IMAGE_DOS_HEADER* dos = Ptr<IMAGE_DOS_HEADER>(0);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            err = L"Signature MZ absente.";
            return false;
        }
        if (dos->e_lfanew <= 0 || (uint64_t)dos->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > b.size()) {
            err = L"Offset PE invalide.";
            return false;
        }
        uint32_t peSig = ReadU32((size_t)dos->e_lfanew);
        if (peSig != IMAGE_NT_SIGNATURE) {
            err = L"Signature PE\\0\\0 absente.";
            return false;
        }

        size_t fhOff = (size_t)dos->e_lfanew + sizeof(uint32_t);
        const IMAGE_FILE_HEADER* fh = Ptr<IMAGE_FILE_HEADER>(fhOff);
        if (!fh) {
            err = L"Header COFF invalide.";
            return false;
        }
        info.machine = fh->Machine;
        info.sectionsCount = fh->NumberOfSections;
        info.timestamp = fh->TimeDateStamp;

        size_t optOff = fhOff + sizeof(IMAGE_FILE_HEADER);
        if (optOff + fh->SizeOfOptionalHeader > b.size()) {
            err = L"Optional header tronque.";
            return false;
        }
        uint16_t magic = ReadU16(optOff);
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const IMAGE_OPTIONAL_HEADER64* oh = Ptr<IMAGE_OPTIONAL_HEADER64>(optOff);
            if (!oh) { err = L"Optional header 64 invalide."; return false; }
            info.is64 = true;
            info.imageBase = oh->ImageBase;
            info.entryRva = oh->AddressOfEntryPoint;
            info.subsystem = oh->Subsystem;
            ReadDirectories64(*oh, info);
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const IMAGE_OPTIONAL_HEADER32* oh = Ptr<IMAGE_OPTIONAL_HEADER32>(optOff);
            if (!oh) { err = L"Optional header 32 invalide."; return false; }
            info.is64 = false;
            info.imageBase = oh->ImageBase;
            info.entryRva = oh->AddressOfEntryPoint;
            info.subsystem = oh->Subsystem;
            ReadDirectories32(*oh, info);
        } else {
            err = L"Magic PE inconnu: " + Hex64(magic, 4);
            return false;
        }

        size_t secOff = optOff + fh->SizeOfOptionalHeader;
        for (uint16_t i = 0; i < fh->NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER* sh = Ptr<IMAGE_SECTION_HEADER>(secOff + i * sizeof(IMAGE_SECTION_HEADER));
            if (!sh) break;
            SectionInfo s;
            char name[9]{};
            memcpy(name, sh->Name, 8);
            s.name = Utf8ToWide(std::string(name));
            s.va = sh->VirtualAddress;
            s.vs = sh->Misc.VirtualSize;
            s.raw = sh->PointerToRawData;
            s.rawSize = sh->SizeOfRawData;
            s.characteristics = sh->Characteristics;
            info.sections.push_back(s);
        }

        ParseImports(info);
        ParseRuntimeFunctions(info);
        info.valid = true;
        return true;
    }

    uint32_t RvaToOffset(uint32_t rva, const std::vector<SectionInfo>& sections) const {
        for (const auto& s : sections) {
            uint32_t span = std::max<uint32_t>(s.vs, s.rawSize);
            if (span == 0) continue;
            if (rva >= s.va && rva < s.va + span) {
                uint64_t off = (uint64_t)s.raw + (rva - s.va);
                if (off < b.size()) return (uint32_t)off;
            }
        }
        if (rva < b.size()) return rva;
        return 0;
    }

private:
    const std::vector<uint8_t>& b;

    template<typename T>
    const T* Ptr(size_t off) const {
        if (off > b.size() || sizeof(T) > b.size() - off) return nullptr;
        return reinterpret_cast<const T*>(b.data() + off);
    }
    uint16_t ReadU16(size_t off) const {
        const uint16_t* p = Ptr<uint16_t>(off);
        return p ? *p : 0;
    }
    uint32_t ReadU32(size_t off) const {
        const uint32_t* p = Ptr<uint32_t>(off);
        return p ? *p : 0;
    }
    uint64_t ReadU64(size_t off) const {
        const uint64_t* p = Ptr<uint64_t>(off);
        return p ? *p : 0;
    }
    std::string ReadAsciiZ(size_t off, size_t maxLen = 4096) const {
        std::string s;
        for (size_t i = 0; i < maxLen && off + i < b.size(); ++i) {
            char c = (char)b[off + i];
            if (c == 0) break;
            if ((uint8_t)c < 9) break;
            s.push_back(c);
        }
        return s;
    }
    void ReadDirectories32(const IMAGE_OPTIONAL_HEADER32& oh, PeInfo& info) {
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            info.importRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            info.importSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            info.exportRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            info.exportSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            info.resourceRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            info.resourceSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            info.exceptionRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            info.exceptionSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        }
    }
    void ReadDirectories64(const IMAGE_OPTIONAL_HEADER64& oh, PeInfo& info) {
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            info.importRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            info.importSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            info.exportRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            info.exportSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            info.resourceRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            info.resourceSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        }
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            info.exceptionRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            info.exceptionSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        }
    }

    void ParseRuntimeFunctions(PeInfo& info) {
        // x64 PE : IMAGE_DIRECTORY_ENTRY_EXCEPTION pointe généralement vers .pdata.
        // Chaque entrée RUNTIME_FUNCTION donne BeginRVA/EndRVA/UnwindInfoRVA et constitue
        // une source beaucoup plus fiable que la recherche de prologues pour les binaires modernes.
        if (!info.is64 || !info.exceptionRva || info.exceptionSize < 12 || info.sections.empty()) return;
        uint32_t off = RvaToOffset(info.exceptionRva, info.sections);
        if (!off) return;
        size_t maxEntries = std::min<size_t>((size_t)info.exceptionSize / 12u, 2000000u);
        for (size_t i = 0; i < maxEntries; ++i) {
            size_t eoff = (size_t)off + i * 12u;
            if (eoff + 12u > b.size()) break;
            RuntimeFunctionInfo rf;
            rf.beginRva = ReadU32(eoff + 0);
            rf.endRva = ReadU32(eoff + 4);
            rf.unwindRva = ReadU32(eoff + 8);
            if (!rf.beginRva && !rf.endRva && !rf.unwindRva) continue;
            if (rf.endRva <= rf.beginRva) continue;
            // Défense anti-table corrompue : bornes raisonnables dans l'image.
            if (rf.endRva - rf.beginRva > 0x1000000u) continue;
            rf.beginVa = info.imageBase + rf.beginRva;
            rf.endVa = info.imageBase + rf.endRva;
            info.runtimeFunctions.push_back(rf);
        }
        std::sort(info.runtimeFunctions.begin(), info.runtimeFunctions.end(), [](const RuntimeFunctionInfo& a, const RuntimeFunctionInfo& b) {
            return a.beginRva < b.beginRva;
        });
        info.runtimeFunctions.erase(std::unique(info.runtimeFunctions.begin(), info.runtimeFunctions.end(), [](const RuntimeFunctionInfo& a, const RuntimeFunctionInfo& b) {
            return a.beginRva == b.beginRva && a.endRva == b.endRva;
        }), info.runtimeFunctions.end());
    }

    void ParseImports(PeInfo& info) {
        if (!info.importRva || info.sections.empty()) return;
        uint32_t impOff = RvaToOffset(info.importRva, info.sections);
        if (!impOff) return;

        for (uint32_t idx = 0; idx < 2048; ++idx) {
            const IMAGE_IMPORT_DESCRIPTOR* d = Ptr<IMAGE_IMPORT_DESCRIPTOR>((size_t)impOff + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!d) break;
            if (!d->Name && !d->FirstThunk && !d->OriginalFirstThunk) break;
            uint32_t nameOff = RvaToOffset(d->Name, info.sections);
            std::wstring dll = nameOff ? Utf8ToWide(ReadAsciiZ(nameOff, 512)) : L"<dll?>";
            uint32_t thunkRva = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
            uint32_t thunkOff = RvaToOffset(thunkRva, info.sections);
            uint32_t iatRvaBase = d->FirstThunk;
            if (!thunkOff || !iatRvaBase) continue;

            for (uint32_t j = 0; j < 4096; ++j) {
                ImportEntry e;
                e.dll = dll;
                e.descriptorIndex = idx;
                e.thunkIndex = j;
                e.lookupRva = thunkRva + j * (info.is64 ? 8u : 4u);
                e.iatRva = iatRvaBase + j * (info.is64 ? 8u : 4u);
                e.iatVa = info.imageBase + e.iatRva;
                if (info.is64) {
                    uint64_t v = ReadU64((size_t)thunkOff + j * sizeof(uint64_t));
                    if (!v) break;
                    if (v & IMAGE_ORDINAL_FLAG64) {
                        e.byOrdinal = true;
                        e.ordinal = (uint16_t)(v & 0xFFFF);
                        e.name = L"#" + Dec(e.ordinal);
                    } else {
                        e.hintNameRva = (uint32_t)v;
                        uint32_t hnOff = RvaToOffset((uint32_t)v, info.sections);
                        if (!hnOff) continue;
                        e.ordinal = ReadU16(hnOff);
                        e.name = Utf8ToWide(ReadAsciiZ(hnOff + 2, 512));
                    }
                } else {
                    uint32_t v = ReadU32((size_t)thunkOff + j * sizeof(uint32_t));
                    if (!v) break;
                    if (v & IMAGE_ORDINAL_FLAG32) {
                        e.byOrdinal = true;
                        e.ordinal = (uint16_t)(v & 0xFFFF);
                        e.name = L"#" + Dec(e.ordinal);
                    } else {
                        e.hintNameRva = v;
                        uint32_t hnOff = RvaToOffset(v, info.sections);
                        if (!hnOff) continue;
                        e.ordinal = ReadU16(hnOff);
                        e.name = Utf8ToWide(ReadAsciiZ(hnOff + 2, 512));
                    }
                }
                if (!e.name.empty()) info.imports.push_back(e);
            }
        }
    }
};

// --------------------------- Helpers PE ---------------------------
static std::wstring MachineName(uint16_t m) {
    switch (m) {
    case IMAGE_FILE_MACHINE_I386: return L"x86 / I386";
    case IMAGE_FILE_MACHINE_AMD64: return L"x64 / AMD64";
    case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
    case IMAGE_FILE_MACHINE_ARMNT: return L"ARM Thumb-2";
    default: return L"Inconnu " + Hex64(m, 4);
    }
}

static std::wstring SubsystemName(uint32_t s) {
    switch (s) {
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Console";
    case IMAGE_SUBSYSTEM_NATIVE: return L"Native";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI Application";
    default: return L"Inconnu " + Dec(s);
    }
}

static bool HasImport(const PeInfo& pi, const std::wstring& needle) {
    for (const auto& i : pi.imports) {
        std::wstring n = i.name;
        std::transform(n.begin(), n.end(), n.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
        std::wstring q = needle;
        std::transform(q.begin(), q.end(), q.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
        if (n.find(q) != std::wstring::npos) return true;
    }
    return false;
}

// --------------------------- Extraction de chaînes ---------------------------
static std::vector<std::wstring> ExtractAsciiStrings(size_t minLen = 5, size_t maxCount = 800) {
    std::vector<std::wstring> out;
    std::string cur;
    size_t start = 0;
    for (size_t i = 0; i < g_file.size(); ++i) {
        if (IsPrintableAscii(g_file[i])) {
            if (cur.empty()) start = i;
            cur.push_back((char)g_file[i]);
        } else {
            if (cur.size() >= minLen) {
                std::wstringstream ss;
                ss << L"[ascii @ " << Hex64(start, 8) << L"] " << Utf8ToWide(cur);
                out.push_back(ss.str());
                if (out.size() >= maxCount) return out;
            }
            cur.clear();
        }
    }
    if (cur.size() >= minLen && out.size() < maxCount) {
        std::wstringstream ss;
        ss << L"[ascii @ " << Hex64(start, 8) << L"] " << Utf8ToWide(cur);
        out.push_back(ss.str());
    }
    return out;
}

static std::vector<std::wstring> ExtractUtf16Strings(size_t minLen = 5, size_t maxCount = 400) {
    std::vector<std::wstring> out;
    std::wstring cur;
    size_t start = 0;
    for (size_t i = 0; i + 1 < g_file.size(); i += 2) {
        uint16_t ch = (uint16_t)g_file[i] | ((uint16_t)g_file[i + 1] << 8);
        if (ch >= 32 && ch <= 126) {
            if (cur.empty()) start = i;
            cur.push_back((wchar_t)ch);
        } else {
            if (cur.size() >= minLen) {
                std::wstringstream ss;
                ss << L"[utf16 @ " << Hex64(start, 8) << L"] " << cur;
                out.push_back(ss.str());
                if (out.size() >= maxCount) return out;
            }
            cur.clear();
        }
    }
    return out;
}

// --------------------------- Désassemblage et décompilation ---------------------------
struct BasicBlock {
    uint64_t start = 0;
    uint64_t end = 0;
    std::vector<std::wstring> instructions;
    std::wstring type;
    uint64_t target = 0;
    std::vector<uint64_t> successors;
    std::vector<uint64_t> calls;
    std::vector<std::wstring> importCalls;
    bool fallthrough = false;
};

struct ThunkInfo {
    uint64_t va = 0;
    std::wstring importName;
    std::wstring pattern;
};

struct JumpTableInfo {
    uint64_t instrVa = 0;
    uint64_t tableVa = 0;
    std::wstring operand;
};

struct AdvancedSectionResult {
    std::wstring name;
    uint64_t start = 0;
    uint64_t end = 0;
    std::vector<BasicBlock> blocks;
    std::vector<ThunkInfo> thunks;
    std::vector<JumpTableInfo> jumpTables;
};

struct IndirectCallInfo {
    uint64_t va = 0;
    std::wstring kind;
    std::wstring operand;
    std::wstring resolution;
};

struct SsaFact {
    uint64_t va = 0;
    std::wstring lhs;
    std::wstring rhs;
    unsigned version = 0;
};

struct TypeHint {
    std::wstring symbol;
    std::wstring inferredType;
    std::wstring evidence;
};

struct CppClassHint {
    uint64_t va = 0;
    std::wstring name;
    std::wstring evidence;
};

struct ExceptionHint {
    std::wstring handler;
    std::wstring evidence;
};

struct CodeQualityMetrics {
    double entropy = 0.0;
    double dbRatio = 0.0;
    size_t totalInstructions = 0;
    size_t dbInstructions = 0;
    size_t callCount = 0;
    size_t branchCount = 0;
    size_t retCount = 0;
    bool probablyPackedOrEncrypted = false;
    std::wstring verdict;
};

// V16 : mode exhaustif par défaut, mais les sections x64 avec .pdata sont analysées par plages de fonctions.
// Cela évite de transformer 30-100 Mo de données/protection en faux pseudo-C linéaire.
// timeoutSeconds=0 signifie : pas de timeout temporel dans les boucles de désassemblage.
static const size_t ZC_MAX_SECTION_ANALYZE_BYTES = (std::numeric_limits<size_t>::max)();
static const size_t ZC_MAX_LINEAR_INSTRUCTIONS = (std::numeric_limits<size_t>::max)();
static const size_t ZC_MAX_RECURSIVE_INSTRUCTIONS = (std::numeric_limits<size_t>::max)();
static const size_t ZC_MAX_REPORT_INSTRUCTIONS_PER_SECTION = 12000u;
static const size_t ZC_MAX_FUNCTION_INDEX_EXPORT = 250000u;
static const int ZC_RECURSIVE_TIMEOUT_SECONDS = 0;
static const int ZC_LINEAR_TIMEOUT_SECONDS = 0;
static const double ZC_PACKED_ENTROPY_THRESHOLD = 7.25;
static const double ZC_STRONG_PACKED_ENTROPY_THRESHOLD = 7.65;
static const double ZC_DB_RATIO_SUSPICIOUS = 0.35;

static std::wstring TrimW(const std::wstring& in) {
    size_t a = 0;
    while (a < in.size() && iswspace(in[a])) a++;
    size_t b = in.size();
    while (b > a && iswspace(in[b - 1])) b--;
    return in.substr(a, b - a);
}

static std::wstring LowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::wstring StripAddressFromDisasmLine(const std::wstring& line) {
    // Format interne attendu : 0x00401000  mnemonic operands
    size_t p = line.find(L"  ");
    if (p != std::wstring::npos) return TrimW(line.substr(p + 2));

    // Fallback défensif si l'espacement a été modifié.
    p = line.find(L' ');
    if (p != std::wstring::npos) return TrimW(line.substr(p + 1));
    return TrimW(line);
}

static std::wstring MnemonicFromAsmText(const std::wstring& asmText) {
    std::wstring t = TrimW(asmText);
    size_t p = t.find_first_of(L" \t");
    if (p == std::wstring::npos) return LowerW(t);
    return LowerW(t.substr(0, p));
}

static std::wstring OperandsFromAsmText(const std::wstring& asmText) {
    std::wstring t = TrimW(asmText);
    size_t p = t.find_first_of(L" \t");
    if (p == std::wstring::npos) return L"";
    return TrimW(t.substr(p + 1));
}

static std::vector<std::wstring> SplitOperands(const std::wstring& operands) {
    std::vector<std::wstring> out;
    std::wstring cur;
    int bracketDepth = 0;
    for (wchar_t ch : operands) {
        if (ch == L'[') bracketDepth++;
        if (ch == L']' && bracketDepth > 0) bracketDepth--;
        if (ch == L',' && bracketDepth == 0) {
            out.push_back(TrimW(cur));
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!TrimW(cur).empty()) out.push_back(TrimW(cur));
    return out;
}

static std::wstring SanitizeCOperand(std::wstring op) {
    op = TrimW(op);
    // Réduction de bruit Capstone : conserver le sens sans prétendre produire du C compilable.
    const std::vector<std::wstring> noise = {
        L"byte ptr ", L"word ptr ", L"dword ptr ", L"qword ptr ",
        L"tbyte ptr ", L"xmmword ptr ", L"ymmword ptr ", L"zmmword ptr ",
        L"ptr "
    };
    std::wstring low = LowerW(op);
    for (const auto& n : noise) {
        if (low.find(n) == 0) {
            op = TrimW(op.substr(n.size()));
            low = LowerW(op);
            break;
        }
    }
    return op;
}

static bool IsConditionalJumpMnemonic(const std::wstring& mn) {
    if (mn.size() < 2 || mn[0] != L'j') return false;
    if (mn == L"jmp" || mn == L"jecxz" || mn == L"jrcxz") return false;
    return true;
}

static std::wstring CondExprForJump(const std::wstring& mn) {
    if (mn == L"je" || mn == L"jz") return L"ZF";
    if (mn == L"jne" || mn == L"jnz") return L"!ZF";
    if (mn == L"ja" || mn == L"jnbe") return L"CF == 0 && ZF == 0";
    if (mn == L"jae" || mn == L"jnb" || mn == L"jnc") return L"CF == 0";
    if (mn == L"jb" || mn == L"jnae" || mn == L"jc") return L"CF == 1";
    if (mn == L"jbe" || mn == L"jna") return L"CF == 1 || ZF == 1";
    if (mn == L"jg" || mn == L"jnle") return L"ZF == 0 && SF == OF";
    if (mn == L"jge" || mn == L"jnl") return L"SF == OF";
    if (mn == L"jl" || mn == L"jnge") return L"SF != OF";
    if (mn == L"jle" || mn == L"jng") return L"ZF == 1 || SF != OF";
    if (mn == L"jo") return L"OF";
    if (mn == L"jno") return L"!OF";
    if (mn == L"js") return L"SF";
    if (mn == L"jns") return L"!SF";
    if (mn == L"jp" || mn == L"jpe") return L"PF";
    if (mn == L"jnp" || mn == L"jpo") return L"!PF";
    return L"condition";
}

static uint64_t ParseLastHexImmediate(const std::wstring& text) {
    uint64_t value = 0;
    size_t pos = 0;
    while ((pos = text.find(L"0x", pos)) != std::wstring::npos) {
        const wchar_t* p = text.c_str() + pos;
        wchar_t* endp = nullptr;
        uint64_t v = _wcstoui64(p, &endp, 16);
        if (endp && endp > p) value = v;
        pos += 2;
    }
    return value;
}

static std::wstring LabelForAddress(uint64_t addr) {
    std::wstringstream ss;
    ss << L"label_" << std::uppercase << std::hex << addr;
    return ss.str();
}

static std::wstring SubNameForTarget(uint64_t addr) {
    std::wstringstream ss;
    ss << L"sub_" << std::uppercase << std::hex << addr;
    return ss.str();
}

// Déclarations nécessaires : ces helpers sont définis plus bas,
// mais utilisés par la génération pseudo-C dès cette zone.
static std::wstring EscapeCStringW(const std::wstring& s);
static std::wstring SanitizeIdentifier(std::wstring s);


static std::wstring StripAsmTrailingComment(std::wstring s) {
    bool inBracket = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == L'[') inBracket = true;
        else if (s[i] == L']') inBracket = false;
        else if (s[i] == L';' && !inBracket) {
            return TrimW(s.substr(0, i));
        }
    }
    return TrimW(s);
}

static bool IsRegisterOperand(const std::wstring& op) {
    std::wstring x = LowerW(TrimW(op));
    static const wchar_t* regs[] = {
        L"al",L"ah",L"ax",L"eax",L"rax",
        L"bl",L"bh",L"bx",L"ebx",L"rbx",
        L"cl",L"ch",L"cx",L"ecx",L"rcx",
        L"dl",L"dh",L"dx",L"edx",L"rdx",
        L"si",L"esi",L"rsi",L"di",L"edi",L"rdi",
        L"sp",L"esp",L"rsp",L"bp",L"ebp",L"rbp",
        L"r8",L"r9",L"r10",L"r11",L"r12",L"r13",L"r14",L"r15",
        L"rip",L"eip",L"cs",L"ds",L"es",L"fs",L"gs",L"ss"
    };
    for (const auto* r : regs) {
        if (x == r) return true;
    }
    return false;
}

static std::wstring CpuFieldForRegister(const std::wstring& op) {
    std::wstring x = LowerW(TrimW(op));
    if (x == L"al" || x == L"ah" || x == L"ax") return L"cpu.eax";
    if (x == L"bl" || x == L"bh" || x == L"bx") return L"cpu.ebx";
    if (x == L"cl" || x == L"ch" || x == L"cx") return L"cpu.ecx";
    if (x == L"dl" || x == L"dh" || x == L"dx") return L"cpu.edx";
    if (x == L"si") return L"cpu.esi";
    if (x == L"di") return L"cpu.edi";
    if (x == L"sp") return L"cpu.esp";
    if (x == L"bp") return L"cpu.ebp";
    if (x == L"rip" || x == L"eip") return L"cpu.ip";
    if (x == L"cs" || x == L"ds" || x == L"es" || x == L"fs" || x == L"gs" || x == L"ss") return L"cpu.seg";
    return L"cpu." + x;
}

static bool IsMemoryOperand(const std::wstring& op) {
    std::wstring x = TrimW(op);
    return !x.empty() && x.front() == L'[' && x.back() == L']';
}

static bool IsImmediateOperand(const std::wstring& op) {
    std::wstring x = LowerW(TrimW(op));
    if (x.empty()) return false;
    if (x.find(L"0x") == 0) return true;
    if (x[0] == L'-' || (x[0] >= L'0' && x[0] <= L'9')) return true;
    return false;
}

static std::wstring CStringLiteralW(const std::wstring& x) {
    return L"\"" + EscapeCStringW(x) + L"\"";
}

static std::wstring CReadExprForOperand(const std::wstring& op) {
    std::wstring x = StripAsmTrailingComment(SanitizeCOperand(op));
    if (x.empty()) return L"0";
    if (IsRegisterOperand(x)) return CpuFieldForRegister(x);
    if (IsMemoryOperand(x)) return L"zc_read64(&cpu, " + CStringLiteralW(x) + L")";
    if (IsImmediateOperand(x)) return x;
    return L"zc_symbol(&cpu, " + CStringLiteralW(x) + L")";
}

static std::wstring CWriteStmtForOperand(const std::wstring& dst, const std::wstring& value) {
    std::wstring d = StripAsmTrailingComment(SanitizeCOperand(dst));
    if (IsRegisterOperand(d)) return CpuFieldForRegister(d) + L" = " + value + L";";
    if (IsMemoryOperand(d)) return L"zc_write64(&cpu, " + CStringLiteralW(d) + L", " + value + L");";
    return L"zc_assign(&cpu, " + CStringLiteralW(d) + L", " + value + L");";
}

static std::wstring JumpTargetString(const std::vector<std::wstring>& ops) {
    if (ops.empty()) return L"";
    return StripAsmTrailingComment(SanitizeCOperand(ops[0]));
}

static void ReplaceAllW(std::wstring& s, const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return;
    size_t p = 0;
    while ((p = s.find(a, p)) != std::wstring::npos) {
        s.replace(p, a.size(), b);
        p += b.size();
    }
}

static std::wstring CFlagExprForJump(const std::wstring& mn) {
    std::wstring c = CondExprForJump(mn);
    ReplaceAllW(c, L"ZF", L"cpu.ZF");
    ReplaceAllW(c, L"CF", L"cpu.CF");
    ReplaceAllW(c, L"SF", L"cpu.SF");
    ReplaceAllW(c, L"OF", L"cpu.OF");
    ReplaceAllW(c, L"PF", L"cpu.PF");
    if (c == L"condition") return L"zc_unknown_condition(&cpu)";
    return c;
}

static std::wstring PseudoFromInstruction(const std::wstring& line) {
    std::wstring asmText = StripAddressFromDisasmLine(line);
    if (asmText.empty()) return L"";

    std::wstring mn = MnemonicFromAsmText(asmText);
    std::wstring opsText = StripAsmTrailingComment(OperandsFromAsmText(asmText));
    auto ops = SplitOperands(opsText);
    for (auto& opx : ops) opx = StripAsmTrailingComment(SanitizeCOperand(opx));

    auto op = [&](size_t i) -> std::wstring { return i < ops.size() ? ops[i] : L""; };
    auto read = [&](size_t i) -> std::wstring { return i < ops.size() ? CReadExprForOperand(ops[i]) : L"0"; };
    auto write = [&](size_t i, const std::wstring& v) -> std::wstring { return i < ops.size() ? CWriteStmtForOperand(ops[i], v) : L""; };

    if (mn.empty()) return L"";
    if (mn == L"db") return L""; // les octets bruts sont traités comme données, pas comme pseudo-code.
    if (mn == L"ret" || mn == L"retf") return L"return;";
    if (mn == L"nop") return L"/* nop */";
    if (mn == L"int3") return L"zc_trap(&cpu);";
    if (mn == L"leave") return L"cpu.esp = cpu.ebp; cpu.ebp = zc_pop(&cpu);";

    if ((mn == L"mov" || mn == L"movabs" || mn == L"movzx" || mn == L"movsx" || mn == L"movsxd") && ops.size() >= 2)
        return write(0, read(1));
    if (mn == L"lea" && ops.size() >= 2)
        return write(0, L"zc_address(&cpu, " + CStringLiteralW(op(1)) + L")");

    if (mn == L"xor" && ops.size() >= 2) {
        if (LowerW(op(0)) == LowerW(op(1)) && IsRegisterOperand(op(0))) return write(0, L"0");
        return write(0, L"(" + read(0) + L" ^ " + read(1) + L")");
    }
    if (mn == L"add" && ops.size() >= 2) return write(0, L"(" + read(0) + L" + " + read(1) + L")");
    if (mn == L"adc" && ops.size() >= 2) return write(0, L"(" + read(0) + L" + " + read(1) + L" + (cpu.CF ? 1 : 0))");
    if (mn == L"sub" && ops.size() >= 2) return write(0, L"(" + read(0) + L" - " + read(1) + L")");
    if (mn == L"sbb" && ops.size() >= 2) return write(0, L"(" + read(0) + L" - " + read(1) + L" - (cpu.CF ? 1 : 0))");
    if (mn == L"and" && ops.size() >= 2) return write(0, L"(" + read(0) + L" & " + read(1) + L")");
    if (mn == L"or"  && ops.size() >= 2) return write(0, L"(" + read(0) + L" | " + read(1) + L")");
    if (mn == L"inc" && ops.size() >= 1) return write(0, L"(" + read(0) + L" + 1)");
    if (mn == L"dec" && ops.size() >= 1) return write(0, L"(" + read(0) + L" - 1)");
    if (mn == L"not" && ops.size() >= 1) return write(0, L"(~" + read(0) + L")");
    if (mn == L"neg" && ops.size() >= 1) return write(0, L"(-" + read(0) + L")");
    if ((mn == L"shl" || mn == L"sal") && ops.size() >= 2) return write(0, L"(" + read(0) + L" << " + read(1) + L")");
    if ((mn == L"shr" || mn == L"sar") && ops.size() >= 2) return write(0, L"(" + read(0) + L" >> " + read(1) + L")");
    if ((mn == L"rol" || mn == L"ror") && ops.size() >= 2) return write(0, L"zc_rotate(&cpu, " + CStringLiteralW(mn) + L", " + read(0) + L", " + read(1) + L")");

    if (mn == L"imul") {
        if (ops.size() >= 3) return write(0, L"(" + read(1) + L" * " + read(2) + L")");
        if (ops.size() >= 2) return write(0, L"(" + read(0) + L" * " + read(1) + L")");
        if (ops.size() >= 1) return L"zc_mul_implicit(&cpu, " + read(0) + L", 1);";
    }
    if (mn == L"mul" && ops.size() >= 1) return L"zc_mul_implicit(&cpu, " + read(0) + L", 0);";
    if ((mn == L"div" || mn == L"idiv") && ops.size() >= 1) return L"zc_div_implicit(&cpu, " + read(0) + L", " + (mn == L"idiv" ? L"1" : L"0") + L");";
    if (mn == L"xchg" && ops.size() >= 2) return L"zc_xchg(&cpu, " + CStringLiteralW(op(0)) + L", " + CStringLiteralW(op(1)) + L");";

    if (mn == L"cmp" && ops.size() >= 2) return L"zc_cmp(&cpu, " + read(0) + L", " + read(1) + L");";
    if (mn == L"test" && ops.size() >= 2) return L"zc_test(&cpu, " + read(0) + L", " + read(1) + L");";
    if (mn.size() >= 3 && mn.rfind(L"set", 0) == 0 && ops.size() >= 1) {
        std::wstring j = L"j" + mn.substr(3);
        return write(0, L"(" + CFlagExprForJump(j) + L" ? 1 : 0)");
    }
    if (mn.size() >= 4 && mn.rfind(L"cmov", 0) == 0 && ops.size() >= 2) {
        std::wstring j = L"j" + mn.substr(4);
        return L"if (" + CFlagExprForJump(j) + L") { " + write(0, read(1)) + L" }";
    }

    if (mn == L"push" && ops.size() >= 1) return L"zc_push(&cpu, " + read(0) + L");";
    if (mn == L"pop" && ops.size() >= 1) return write(0, L"zc_pop(&cpu)");
    if (mn == L"pushad" || mn == L"pusha") return L"zc_push_all(&cpu);";
    if (mn == L"popad" || mn == L"popa") return L"zc_pop_all(&cpu);";

    if (mn == L"call") {
        size_t ipos = line.find(L"; import ");
        if (ipos != std::wstring::npos) return L"zc_call(&cpu, " + CStringLiteralW(TrimW(line.substr(ipos + 9))) + L");";
        std::wstring target = JumpTargetString(ops);
        uint64_t addr = ParseLastHexImmediate(target);
        if (addr != 0) return L"zc_call(&cpu, " + CStringLiteralW(SubNameForTarget(addr)) + L");";
        return L"zc_call_indirect(&cpu, " + CStringLiteralW(target.empty() ? opsText : target) + L");";
    }
    if (mn == L"jmp") {
        size_t ipos = line.find(L"; import ");
        if (ipos != std::wstring::npos) return L"zc_jump(&cpu, " + CStringLiteralW(TrimW(line.substr(ipos + 9))) + L");";
        std::wstring target = JumpTargetString(ops);
        uint64_t addr = ParseLastHexImmediate(target);
        if (addr != 0) return L"zc_jump(&cpu, " + CStringLiteralW(LabelForAddress(addr)) + L");";
        return L"zc_jump_indirect(&cpu, " + CStringLiteralW(target.empty() ? opsText : target) + L");";
    }
    if (IsConditionalJumpMnemonic(mn)) {
        std::wstring target = JumpTargetString(ops);
        uint64_t addr = ParseLastHexImmediate(target);
        if (addr != 0) return L"if (" + CFlagExprForJump(mn) + L") { zc_jump(&cpu, " + CStringLiteralW(LabelForAddress(addr)) + L"); }";
        return L"if (" + CFlagExprForJump(mn) + L") { zc_jump_indirect(&cpu, " + CStringLiteralW(target.empty() ? opsText : target) + L"); }";
    }

    if (mn == L"rep" || mn == L"repe" || mn == L"repne" || mn == L"movsb" || mn == L"movsw" || mn == L"movsd" || mn == L"stosb" || mn == L"stosw" || mn == L"stosd" || mn == L"lodsb" || mn == L"scasb") {
        return L"zc_string_op(&cpu, " + CStringLiteralW(asmText) + L");";
    }

    return L"zc_unmodeled(&cpu, " + CStringLiteralW(asmText) + L");";
}

static std::wstring GeneratedCRuntimeHeader(bool cppMode) {
    std::wstringstream code;
    code << (cppMode ? L"#include <cstdint>\n#include <cstdio>\n\n" : L"#include <stdint.h>\n#include <stdio.h>\n#include <stdbool.h>\n\n");
    code << L"typedef struct ZC_CPU {\n";
    code << L"    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;\n";
    code << L"    uint64_t eax, ebx, ecx, edx, esi, edi, ebp, esp;\n";
    code << L"    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;\n";
    code << L"    uint64_t ip, seg;\n";
    code << L"    int ZF, CF, SF, OF, PF;\n";
    code << L"} ZC_CPU;\n\n";
    code << L"static uint64_t zc_read64(ZC_CPU* cpu, const char* expr) { (void)cpu; (void)expr; return 0; }\n";
    code << L"static void zc_write64(ZC_CPU* cpu, const char* expr, uint64_t value) { (void)cpu; (void)expr; (void)value; }\n";
    code << L"static uint64_t zc_symbol(ZC_CPU* cpu, const char* name) { (void)cpu; (void)name; return 0; }\n";
    code << L"static uint64_t zc_address(ZC_CPU* cpu, const char* expr) { (void)cpu; (void)expr; return 0; }\n";
    code << L"static void zc_assign(ZC_CPU* cpu, const char* dst, uint64_t value) { (void)cpu; (void)dst; (void)value; }\n";
    code << L"static void zc_cmp(ZC_CPU* cpu, uint64_t a, uint64_t b) { cpu->ZF = (a == b); cpu->CF = (a < b); cpu->SF = ((int64_t)(a - b) < 0); cpu->OF = 0; cpu->PF = 0; }\n";
    code << L"static void zc_test(ZC_CPU* cpu, uint64_t a, uint64_t b) { uint64_t r = a & b; cpu->ZF = (r == 0); cpu->SF = ((int64_t)r < 0); cpu->CF = 0; cpu->OF = 0; cpu->PF = 0; }\n";
    code << L"static void zc_push(ZC_CPU* cpu, uint64_t value) { (void)value; cpu->rsp -= 8; cpu->esp -= 4; }\n";
    code << L"static uint64_t zc_pop(ZC_CPU* cpu) { cpu->rsp += 8; cpu->esp += 4; return 0; }\n";
    code << L"static void zc_call(ZC_CPU* cpu, const char* target) { (void)cpu; (void)target; }\n";
    code << L"static void zc_call_indirect(ZC_CPU* cpu, const char* target) { (void)cpu; (void)target; }\n";
    code << L"static void zc_jump(ZC_CPU* cpu, const char* target) { (void)cpu; (void)target; }\n";
    code << L"static void zc_jump_indirect(ZC_CPU* cpu, const char* target) { (void)cpu; (void)target; }\n";
    code << L"static uint64_t zc_rotate(ZC_CPU* cpu, const char* dir, uint64_t a, uint64_t b) { (void)cpu; (void)dir; (void)b; return a; }\n";
    code << L"static void zc_mul_implicit(ZC_CPU* cpu, uint64_t value, int sign) { (void)cpu; (void)value; (void)sign; }\n";
    code << L"static void zc_div_implicit(ZC_CPU* cpu, uint64_t value, int sign) { (void)cpu; (void)value; (void)sign; }\n";
    code << L"static void zc_xchg(ZC_CPU* cpu, const char* a, const char* b) { (void)cpu; (void)a; (void)b; }\n";
    code << L"static void zc_string_op(ZC_CPU* cpu, const char* op) { (void)cpu; (void)op; }\n";
    code << L"static void zc_unmodeled(ZC_CPU* cpu, const char* op) { (void)cpu; (void)op; }\n";
    code << L"static void zc_push_all(ZC_CPU* cpu) { (void)cpu; }\n";
    code << L"static void zc_pop_all(ZC_CPU* cpu) { (void)cpu; }\n";
    code << L"static void zc_trap(ZC_CPU* cpu) { (void)cpu; }\n";
    code << L"static int zc_unknown_condition(ZC_CPU* cpu) { (void)cpu; return 0; }\n";
    code << L"static void ZC_OP(const char* op, const char* a) { (void)op; (void)a; }\n\n";
    return code.str();
}
static uint64_t InstructionAddressFromLine(const std::wstring& line) {
    size_t p = line.find(L"0x");
    if (p == std::wstring::npos) return 0;
    wchar_t* endp = nullptr;
    uint64_t v = _wcstoui64(line.c_str() + p, &endp, 16);
    return (endp && endp > line.c_str() + p) ? v : 0;
}

static bool IsCallMnemonic(const std::wstring& mn) { return mn == L"call"; }
static bool IsUnconditionalJumpMnemonic(const std::wstring& mn) { return mn == L"jmp"; }
static bool IsReturnMnemonic(const std::wstring& mn) { return mn == L"ret" || mn == L"retf"; }
static bool IsBranchLikeMnemonic(const std::wstring& mn) {
    return IsCallMnemonic(mn) || IsUnconditionalJumpMnemonic(mn) || IsReturnMnemonic(mn) || IsConditionalJumpMnemonic(mn);
}

static std::vector<BasicBlock> BuildBasicBlocks(const std::map<uint64_t, std::wstring>& disasm) {
    std::vector<BasicBlock> blocks;
    if (disasm.empty()) return blocks;

    std::vector<uint64_t> addresses;
    addresses.reserve(disasm.size());
    for (const auto& kv : disasm) addresses.push_back(kv.first);

    std::set<uint64_t> blockStarts;
    blockStarts.insert(addresses.front());

    for (size_t i = 0; i < addresses.size(); ++i) {
        uint64_t addr = addresses[i];
        auto itLine = disasm.find(addr);
        if (itLine == disasm.end()) continue;
        std::wstring asmText = StripAddressFromDisasmLine(itLine->second);
        std::wstring mn = MnemonicFromAsmText(asmText);
        std::wstring opsText = OperandsFromAsmText(asmText);
        uint64_t target = ParseLastHexImmediate(opsText);

        if ((IsUnconditionalJumpMnemonic(mn) || IsConditionalJumpMnemonic(mn) || IsCallMnemonic(mn)) && target && disasm.find(target) != disasm.end()) {
            blockStarts.insert(target);
        }
        if (IsBranchLikeMnemonic(mn) && i + 1 < addresses.size()) {
            blockStarts.insert(addresses[i + 1]);
        }
    }

    std::vector<uint64_t> starts(blockStarts.begin(), blockStarts.end());
    std::map<uint64_t, size_t> startToIndex;

    for (size_t i = 0; i < starts.size(); ++i) {
        BasicBlock block;
        block.start = starts[i];
        uint64_t nextStart = (i + 1 < starts.size()) ? starts[i + 1] : UINT64_MAX;
        for (auto it = disasm.lower_bound(block.start); it != disasm.end() && it->first < nextStart; ++it) {
            block.instructions.push_back(it->second);
            block.end = it->first;
        }
        if (block.instructions.empty()) continue;

        std::wstring lastAsm = StripAddressFromDisasmLine(block.instructions.back());
        std::wstring mn = MnemonicFromAsmText(lastAsm);
        block.target = ParseLastHexImmediate(OperandsFromAsmText(lastAsm));

        if (IsReturnMnemonic(mn)) block.type = L"return";
        else if (IsUnconditionalJumpMnemonic(mn)) block.type = L"jump";
        else if (IsConditionalJumpMnemonic(mn)) block.type = L"condition";
        else if (IsCallMnemonic(mn)) block.type = L"call";
        else block.type = L"basic";

        // Appels intra-section détectés dans tout le bloc.
        for (const auto& instr : block.instructions) {
            std::wstring a = StripAddressFromDisasmLine(instr);
            std::wstring imn = MnemonicFromAsmText(a);
            if (IsCallMnemonic(imn)) {
                uint64_t t = ParseLastHexImmediate(OperandsFromAsmText(a));
                if (t) block.calls.push_back(t);
                size_t ip = instr.find(L"; import ");
                if (ip != std::wstring::npos) block.importCalls.push_back(TrimW(instr.substr(ip + 9)));
            }
        }

        blocks.push_back(block);
        startToIndex[block.start] = blocks.size() - 1;
    }

    std::set<uint64_t> blockStartSet;
    for (const auto& b : blocks) blockStartSet.insert(b.start);

    for (size_t i = 0; i < blocks.size(); ++i) {
        BasicBlock& b = blocks[i];
        std::wstring lastAsm = StripAddressFromDisasmLine(b.instructions.back());
        std::wstring mn = MnemonicFromAsmText(lastAsm);
        uint64_t target = b.target;
        if ((IsUnconditionalJumpMnemonic(mn) || IsConditionalJumpMnemonic(mn)) && target && blockStartSet.count(target)) {
            b.successors.push_back(target);
        }
        if (!IsReturnMnemonic(mn) && !IsUnconditionalJumpMnemonic(mn) && i + 1 < blocks.size()) {
            b.successors.push_back(blocks[i + 1].start);
            b.fallthrough = true;
        }
    }

    return blocks;
}

static std::wstring GeneratePseudoC(const std::vector<BasicBlock>& blocks,
                                    const std::wstring& functionName = L"zenncomp_entry",
                                    bool includeHeader = true,
                                    bool includeAsmComments = true) {
    std::wstringstream code;
    if (includeHeader) code << GeneratedCRuntimeHeader(false);
    code << L"/*\n";
    code << L" * ZennComp V14 - pseudo-décompilation C V14 avec CFG/SSA heuristique.\n";
    code << L" * Sortie orientée audit : CFG, blocs, labels, état CPU symbolique et opérations C-like.\n";
    code << L" * Ce fichier n'est pas une reconstruction bit-à-bit du programme original.\n";
    code << L" */\n\n";
    code << L"void " << SanitizeIdentifier(functionName) << L"(void) {\n";
    code << L"    ZC_CPU cpu = {0};\n";

    for (const auto& block : blocks) {
        code << L"\n";
        code << L"    /* ------------------------------------------------------------ */\n";
        code << L"    /* Bloc " << Hex64(block.start, 8) << L" | type=" << (block.type.empty() ? L"basic" : block.type) << L" | succ=";
        if (block.successors.empty()) code << L"none";
        for (size_t si = 0; si < block.successors.size(); ++si) code << (si ? L", " : L"") << Hex64(block.successors[si], 8);
        code << L" */\n";
        code << L"    " << LabelForAddress(block.start) << L":;\n";

        for (const auto& instr : block.instructions) {
            if (includeAsmComments) code << L"    /* " << instr << L" */\n";
            std::wstring pseudo = PseudoFromInstruction(instr);
            if (!pseudo.empty()) code << L"    " << pseudo << L"\n";
        }
    }

    code << L"}\n";
    return code.str();
}

static std::wstring GeneratePseudoCpp(const std::vector<BasicBlock>& blocks,
                                      const std::wstring& className,
                                      const std::wstring& exportedFunctionName,
                                      bool includeAsmComments = true) {
    std::wstring cls = SanitizeIdentifier(className);
    if (cls.empty()) cls = L"ZennCompModule";
    if (!iswalpha(cls[0]) && cls[0] != L'_') cls = L"ZC_" + cls;

    std::wstringstream code;
    code << GeneratedCRuntimeHeader(true);
    code << L"#include <array>\n#include <string_view>\n\n";
    code << L"namespace zenncomp_rebuild {\n\n";
    code << L"/*\n";
    code << L" * ZennComp V14 - pseudo-décompilation C++ V14 avec CFG/SSA heuristique.\n";
    code << L" * Le flux de contrôle est reconstruit en blocs/labels et l'état CPU est symbolique.\n";
    code << L" */\n";
    code << L"class " << cls << L" final {\n";
    code << L"public:\n";
    code << L"    static void run() {\n";
    code << L"        ZC_CPU cpu = {0};\n";
    for (const auto& block : blocks) {
        code << L"\n";
        code << L"        /* ------------------------------------------------------------ */\n";
        code << L"        /* Bloc " << Hex64(block.start, 8) << L" | type=" << (block.type.empty() ? L"basic" : block.type) << L" | succ=";
        if (block.successors.empty()) code << L"none";
        for (size_t si = 0; si < block.successors.size(); ++si) code << (si ? L", " : L"") << Hex64(block.successors[si], 8);
        code << L" */\n";
        code << L"        " << LabelForAddress(block.start) << L":;\n";
        for (const auto& instr : block.instructions) {
            if (includeAsmComments) code << L"        /* " << instr << L" */\n";
            std::wstring pseudo = PseudoFromInstruction(instr);
            if (!pseudo.empty()) code << L"        " << pseudo << L"\n";
        }
    }
    code << L"    }\n";
    code << L"};\n\n";
    code << L"} // namespace zenncomp_rebuild\n\n";
    code << L"extern \"C\" void " << SanitizeIdentifier(exportedFunctionName) << L"(void) {\n";
    code << L"    zenncomp_rebuild::" << cls << L"::run();\n";
    code << L"}\n";
    return code.str();
}

// --------------------------- Désassemblage avec SEH local ---------------------------
static bool IsPrintableAsciiString(const char* text, size_t maxLen) {
    if (!text) return false;
    bool hasAlpha = false;
    size_t i = 0;
    for (; i < maxLen && text[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c > 0x7E) return false;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) hasAlpha = true;
    }
    return i > 0 && i < maxLen && hasAlpha;
}

static bool IsLikelyValidMnemonic(const cs_insn& insn) {
    return IsPrintableAsciiString(insn.mnemonic, sizeof(insn.mnemonic));
}

static void CheckCapstoneRuntimeOrThrow() {
    int runtimeMajor = 0;
    int runtimeMinor = 0;
    cs_version(&runtimeMajor, &runtimeMinor);

#ifdef CS_API_MAJOR
    if (runtimeMajor != CS_API_MAJOR) {
        std::string msg = "Capstone ABI incompatible : capstone.dll runtime=" +
            std::to_string(runtimeMajor) + "." + std::to_string(runtimeMinor) +
            " alors que les headers de compilation attendent major=" + std::to_string(CS_API_MAJOR) +
            ". Copiez la DLL depuis le dossier bin du meme vcpkg que capstone.lib.";
        throw std::runtime_error(msg);
    }
#endif
}

static bool SafeCsDisasm(csh handle, const uint8_t* code, size_t code_size, uint64_t address,
                         cs_insn** insn, size_t* count) {
    __try {
        *count = cs_disasm(handle, code, code_size, address, 1, insn);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}


static std::wstring EscapeCStringW(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 16);
    for (wchar_t ch : s) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'\"': out += L"\\\""; break;
        case L'\r': out += L"\\r"; break;
        case L'\n': out += L"\\n"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 32) out += L'?';
            else out += ch;
            break;
        }
    }
    return out;
}

static std::wstring SanitizeIdentifier(std::wstring s) {
    if (s.empty()) return L"unnamed";
    for (wchar_t& c : s) {
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'_')) {
            c = L'_';
        }
    }
    if (s.empty() || (s[0] >= L'0' && s[0] <= L'9')) s = L"zc_" + s;
    while (s.find(L"__") != std::wstring::npos) {
        s.replace(s.find(L"__"), 2, L"_");
    }
    if (s.size() > 120) s.resize(120);
    return s;
}

static std::wstring RegNameX86(int idx, bool is64) {
    static const wchar_t* r32[] = {L"eax", L"ecx", L"edx", L"ebx", L"esp", L"ebp", L"esi", L"edi"};
    static const wchar_t* r64[] = {L"rax", L"rcx", L"rdx", L"rbx", L"rsp", L"rbp", L"rsi", L"rdi"};
    idx &= 7;
    return is64 ? r64[idx] : r32[idx];
}

static uint32_t ReadLe32(const uint8_t* p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t ReadLe16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0]) | ((uint16_t)p[1] << 8));
}

static std::wstring SignedHexDisp(int64_t v) {
    std::wstringstream ss;
    if (v < 0) ss << L" - 0x" << std::uppercase << std::hex << (uint64_t)(-v);
    else if (v > 0) ss << L" + 0x" << std::uppercase << std::hex << (uint64_t)v;
    return ss.str();
}

static bool DecodeModRM32(const uint8_t* code, size_t size, size_t& pos, bool is64,
                          std::wstring& rmOp, std::wstring& regOp) {
    if (pos >= size) return false;
    uint8_t modrm = code[pos++];
    int mod = (modrm >> 6) & 3;
    int reg = (modrm >> 3) & 7;
    int rm  = modrm & 7;
    regOp = RegNameX86(reg, is64);

    if (mod == 3) {
        rmOp = RegNameX86(rm, is64);
        return true;
    }

    std::wstring mem = L"[";
    bool hasBase = false;
    bool needDisp32 = false;
    int64_t disp = 0;

    if (rm == 4) {
        if (pos >= size) return false;
        uint8_t sib = code[pos++];
        int scale = (sib >> 6) & 3;
        int index = (sib >> 3) & 7;
        int baseReg = sib & 7;
        if (!(mod == 0 && baseReg == 5)) {
            mem += RegNameX86(baseReg, is64);
            hasBase = true;
        } else {
            needDisp32 = true;
        }
        if (index != 4) {
            if (hasBase) mem += L" + ";
            mem += RegNameX86(index, is64);
            if (scale) mem += L"*" + Dec(uint64_t(1) << scale);
            hasBase = true;
        }
    } else if (mod == 0 && rm == 5) {
        needDisp32 = true;
    } else {
        mem += RegNameX86(rm, is64);
        hasBase = true;
    }

    if (mod == 1) {
        if (pos >= size) return false;
        disp = (int8_t)code[pos++];
    } else if (mod == 2 || needDisp32) {
        if (pos + 4 > size) return false;
        disp = (int32_t)ReadLe32(code + pos);
        pos += 4;
    }

    if (!hasBase && needDisp32) {
        mem += Hex64((uint32_t)disp, 8);
    } else {
        mem += SignedHexDisp(disp);
    }
    mem += L"]";
    rmOp = mem;
    return true;
}

static const wchar_t* JccName8(int low) {
    static const wchar_t* names[16] = {L"jo",L"jno",L"jb",L"jae",L"je",L"jne",L"jbe",L"ja",L"js",L"jns",L"jp",L"jnp",L"jl",L"jge",L"jle",L"jg"};
    return names[low & 0xF];
}

static bool DecodeOneFallbackX86(const uint8_t* code, size_t size, uint64_t address, bool is64,
                                 std::wstring& line, size_t& consumed) {
    line.clear();
    consumed = 0;
    if (!code || size == 0) return false;

    size_t pos = 0;
    std::wstring prefix;
    while (pos < size) {
        uint8_t b = code[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || (is64 && b >= 0x40 && b <= 0x4F)) {
            if (!prefix.empty()) prefix += L" ";
            prefix += L"prefix_" + Hex64(b, 2);
            pos++;
            continue;
        }
        break;
    }
    if (pos >= size) { consumed = 1; line = Hex64(address, 8) + L"  db " + Hex64(code[0], 2); return true; }

    uint8_t op = code[pos++];
    std::wstring mn, ops;

    auto need = [&](size_t n) { return pos + n <= size; };
    auto relTarget8 = [&](int8_t r) { return address + pos + (int64_t)r; };
    auto relTarget32 = [&](int32_t r) { return address + pos + (int64_t)r; };

    if (op >= 0x50 && op <= 0x57) { mn = L"push"; ops = RegNameX86(op - 0x50, is64); }
    else if (op >= 0x58 && op <= 0x5F) { mn = L"pop"; ops = RegNameX86(op - 0x58, is64); }
    else if (op >= 0xB8 && op <= 0xBF && need(4)) { mn = L"mov"; ops = RegNameX86(op - 0xB8, is64) + L", " + Hex64(ReadLe32(code + pos), 8); pos += 4; }
    else if (op == 0x90) { mn = L"nop"; }
    else if (op == 0xCC) { mn = L"int3"; }
    else if (op == 0xC3) { mn = L"ret"; }
    else if (op == 0xC2 && need(2)) { mn = L"ret"; ops = Hex64(ReadLe16(code + pos), 4); pos += 2; }
    else if (op == 0x68 && need(4)) { mn = L"push"; ops = Hex64(ReadLe32(code + pos), 8); pos += 4; }
    else if (op == 0x6A && need(1)) { mn = L"push"; ops = Hex64((uint8_t)code[pos], 2); pos += 1; }
    else if (op == 0xE8 && need(4)) { int32_t r = (int32_t)ReadLe32(code + pos); pos += 4; mn = L"call"; ops = Hex64(relTarget32(r), 8); }
    else if (op == 0xE9 && need(4)) { int32_t r = (int32_t)ReadLe32(code + pos); pos += 4; mn = L"jmp"; ops = Hex64(relTarget32(r), 8); }
    else if (op == 0xEB && need(1)) { int8_t r = (int8_t)code[pos++]; mn = L"jmp"; ops = Hex64(relTarget8(r), 8); }
    else if (op >= 0x70 && op <= 0x7F && need(1)) { int8_t r = (int8_t)code[pos++]; mn = JccName8(op & 0xF); ops = Hex64(relTarget8(r), 8); }
    else if (op == 0x0F && need(1)) {
        uint8_t op2 = code[pos++];
        if (op2 >= 0x80 && op2 <= 0x8F && need(4)) {
            int32_t r = (int32_t)ReadLe32(code + pos); pos += 4; mn = JccName8(op2 & 0xF); ops = Hex64(relTarget32(r), 8);
        } else {
            mn = L"db"; ops = Hex64(0x0F, 2) + L", " + Hex64(op2, 2);
        }
    }
    else {
        std::wstring rm, reg;
        size_t save = pos;
        auto modrm2 = [&]() -> bool { pos = save; return DecodeModRM32(code, size, pos, is64, rm, reg); };
        if ((op == 0x89 || op == 0x8B || op == 0x8D || op == 0x31 || op == 0x33 || op == 0x29 || op == 0x2B || op == 0x01 || op == 0x03 || op == 0x39 || op == 0x3B || op == 0x85 || op == 0x84) && modrm2()) {
            switch (op) {
            case 0x89: mn = L"mov"; ops = rm + L", " + reg; break;
            case 0x8B: mn = L"mov"; ops = reg + L", " + rm; break;
            case 0x8D: mn = L"lea"; ops = reg + L", " + rm; break;
            case 0x31: mn = L"xor"; ops = rm + L", " + reg; break;
            case 0x33: mn = L"xor"; ops = reg + L", " + rm; break;
            case 0x29: mn = L"sub"; ops = rm + L", " + reg; break;
            case 0x2B: mn = L"sub"; ops = reg + L", " + rm; break;
            case 0x01: mn = L"add"; ops = rm + L", " + reg; break;
            case 0x03: mn = L"add"; ops = reg + L", " + rm; break;
            case 0x39: mn = L"cmp"; ops = rm + L", " + reg; break;
            case 0x3B: mn = L"cmp"; ops = reg + L", " + rm; break;
            case 0x85: case 0x84: mn = L"test"; ops = rm + L", " + reg; break;
            }
        } else if ((op == 0x83 || op == 0x81) && modrm2()) {
            uint8_t group = ((code[save] >> 3) & 7);
            std::wstring imm;
            if (op == 0x83 && pos < size) { imm = Hex64((uint8_t)code[pos], 2); pos++; }
            else if (op == 0x81 && pos + 4 <= size) { imm = Hex64(ReadLe32(code + pos), 8); pos += 4; }
            else { imm = L"?"; }
            static const wchar_t* gnames[8] = {L"add",L"or",L"adc",L"sbb",L"and",L"sub",L"xor",L"cmp"};
            mn = gnames[group]; ops = rm + L", " + imm;
        } else if (op == 0xC7 && modrm2() && pos + 4 <= size) {
            mn = L"mov"; ops = rm + L", " + Hex64(ReadLe32(code + pos), 8); pos += 4;
        } else if (op == 0xA1 && need(4)) {
            mn = L"mov"; ops = RegNameX86(0, is64) + L", [" + Hex64(ReadLe32(code + pos), 8) + L"]"; pos += 4;
        } else if (op == 0xA3 && need(4)) {
            mn = L"mov"; ops = L"[" + Hex64(ReadLe32(code + pos), 8) + L"], " + RegNameX86(0, is64); pos += 4;
        } else {
            mn = L"db"; ops = Hex64(op, 2);
        }
    }

    consumed = std::max<size_t>(pos, 1);
    line = Hex64(address, 8) + L"  " + mn;
    if (!ops.empty()) line += L" " + ops;
    if (!prefix.empty()) line += L"    ; " + prefix;
    return true;
}

static std::map<uint64_t, std::wstring> FallbackDisassembleX86(const uint8_t* code, size_t size, uint64_t base, bool is64,
                                                               size_t maxInstructions = ZC_MAX_LINEAR_INSTRUCTIONS,
                                                               int timeoutSeconds = ZC_LINEAR_TIMEOUT_SECONDS) {
    std::map<uint64_t, std::wstring> result;
    if (!code || size == 0) return result;
    auto startTime = std::chrono::steady_clock::now();
    size_t off = 0;
    while (off < size && result.size() < maxInstructions) {
        auto now = std::chrono::steady_clock::now();
        if (timeoutSeconds > 0 && std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() >= timeoutSeconds) break;
        std::wstring line;
        size_t consumed = 0;
        if (!DecodeOneFallbackX86(code + off, size - off, base + off, is64, line, consumed) || consumed == 0) consumed = 1;
        if (!line.empty()) result[base + off] = TrimW(line);
        off += consumed;
    }
    return result;
}

static std::map<uint64_t, std::wstring> BuildDisassembly(const uint8_t* code, size_t size, uint64_t base, bool is64,
                                                         size_t maxInstructions = ZC_MAX_LINEAR_INSTRUCTIONS,
                                                         int timeoutSeconds = ZC_LINEAR_TIMEOUT_SECONDS) {
    std::map<uint64_t, std::wstring> result;
    if (!code || size == 0) return result;

    try {
        CheckCapstoneRuntimeOrThrow();
    } catch (...) {
        return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
    }

    csh handle = 0;
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = is64 ? CS_MODE_64 : CS_MODE_32;

    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    uint64_t address = base;
    const uint8_t* codePtr = code;
    size_t remaining = size;
    int errorCount = 0;
    const int MAX_ERRORS = 64;
    auto startTime = std::chrono::steady_clock::now();

    while (remaining > 0 && errorCount < MAX_ERRORS && result.size() < maxInstructions) {
        auto now = std::chrono::steady_clock::now();
        if (timeoutSeconds > 0 && std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() >= timeoutSeconds) {
            break;
        }

        if (address < base || address >= base + size) {
            errorCount++;
            break;
        }
        size_t offset = address - base;
        if (offset >= size) {
            errorCount++;
            break;
        }

        cs_insn* insn = nullptr;
        size_t count = 0;
        if (!SafeCsDisasm(handle, codePtr, remaining, address, &insn, &count)) {
            errorCount++;
            address++;
            codePtr++;
            remaining--;
            continue;
        }

        if (count == 0) {
            errorCount++;
            address++;
            codePtr++;
            remaining--;
            continue;
        }

        for (size_t i = 0; i < count && result.size() < maxInstructions; ++i) {
            if (insn[i].size == 0 || insn[i].size > remaining) {
                errorCount++;
                break;
            }

            if (!IsLikelyValidMnemonic(insn[i])) {
                cs_free(insn, count);
                cs_close(&handle);
                return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
            }

            std::wstring line;
            line += Hex64(insn[i].address, 8) + L"  ";
            line += Utf8ToWide(insn[i].mnemonic) + L" " + Utf8ToWide(insn[i].op_str);
            result[insn[i].address] = TrimW(line);

            address += insn[i].size;
            codePtr += insn[i].size;
            remaining -= insn[i].size;
            errorCount = 0;
        }

        cs_free(insn, count);
    }

    cs_close(&handle);
    if (result.empty()) {
        result = FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
    }
    return result;
}

static std::map<uint64_t, std::wstring> DisassembleRecursive(const uint8_t* code, size_t size, uint64_t base, bool is64,
                                                               const std::vector<uint64_t>* entryOffsets = nullptr,
                                                               size_t maxInstructions = ZC_MAX_RECURSIVE_INSTRUCTIONS,
                                                               int timeoutSeconds = ZC_RECURSIVE_TIMEOUT_SECONDS) {
    std::map<uint64_t, std::wstring> result;
    if (!code || size == 0) return result;

    try {
        CheckCapstoneRuntimeOrThrow();
    } catch (...) {
        return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
    }

    std::set<uint64_t> visited;
    std::vector<uint64_t> worklist;
    worklist.push_back(base);
    if (entryOffsets) {
        for (uint64_t off : *entryOffsets) {
            if (off < size) worklist.push_back(base + off);
        }
    }

    csh handle = 0;
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = is64 ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    auto startTime = std::chrono::steady_clock::now();
    const int MAX_ERRORS_PER_ENTRY = 24;

    try {
        while (!worklist.empty() && result.size() < maxInstructions) {
            auto now = std::chrono::steady_clock::now();
            if (timeoutSeconds > 0 && std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() >= timeoutSeconds) {
                break;
            }

            uint64_t start = worklist.back();
            worklist.pop_back();
            if (visited.find(start) != visited.end()) continue;
            if (start < base || start >= base + size) continue;
            visited.insert(start);

            uint64_t address = start;
            int errorCount = 0;
            bool ended = false;

            while (!ended && result.size() < maxInstructions && errorCount < MAX_ERRORS_PER_ENTRY) {
                now = std::chrono::steady_clock::now();
                if (timeoutSeconds > 0 && std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() >= timeoutSeconds) {
                    ended = true;
                    break;
                }

                if (address < base || address >= base + size) break;
                size_t offset = (size_t)(address - base);
                if (offset >= size) break;

                const uint8_t* codePtr = code + offset;
                size_t remaining = size - offset;
                if (remaining == 0) break;

                cs_insn* insn = nullptr;
                size_t count = 0;
                if (!SafeCsDisasm(handle, codePtr, remaining, address, &insn, &count) || count == 0 || !insn) {
                    errorCount++;
                    address++;
                    continue;
                }

                const cs_insn& cur = insn[0];
                if (cur.size == 0 || cur.size > remaining) {
                    cs_free(insn, count);
                    errorCount++;
                    address++;
                    continue;
                }

                if (!IsLikelyValidMnemonic(cur)) {
                    cs_free(insn, count);
                    cs_close(&handle);
                    return FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
                }

                std::wstring line;
                line += Hex64(cur.address, 8) + L"  ";
                line += Utf8ToWide(cur.mnemonic) + L" " + Utf8ToWide(cur.op_str);
                result[cur.address] = TrimW(line);

                bool isJump = false;
                bool isCall = false;
                bool isRet = false;
                bool isConditional = false;
                uint64_t target = 0;
                bool hasTarget = false;

                if (cur.id == X86_INS_RET) {
                    isRet = true;
                } else if (cur.id == X86_INS_JMP) {
                    isJump = true;
                } else if (cur.id == X86_INS_CALL) {
                    isCall = true;
                } else if (cur.id >= X86_INS_JA && cur.id <= X86_INS_JNS) {
                    isJump = true;
                    isConditional = true;
                }

                if (cur.detail) {
                    const cs_x86* detail = &cur.detail->x86;
                    if (detail->op_count > 0 && detail->operands[0].type == X86_OP_IMM) {
                        int64_t imm = detail->operands[0].imm;
                        if (imm >= 0) {
                            target = (uint64_t)imm;
                            hasTarget = true;
                        }
                    }
                }

                if ((isJump || isCall) && hasTarget && target >= base && target < base + size && visited.find(target) == visited.end()) {
                    worklist.push_back(target);
                }

                address += cur.size;
                errorCount = 0;

                cs_free(insn, count);

                if (isRet || (isJump && !isConditional)) {
                    ended = true;
                }
            }
        }
    } catch (const std::runtime_error&) {
        cs_close(&handle);
        throw;
    } catch (...) {
        // Une section PE peut contenir du code invalide, chiffré ou volontairement hostile.
        // On retourne le résultat partiel au lieu de faire tomber tout le bruteforce.
    }

    cs_close(&handle);
    if (result.empty()) {
        result = FallbackDisassembleX86(code, size, base, is64, maxInstructions, timeoutSeconds);
    }
    return result;
}

static std::vector<uint64_t> FindFunctionStarts(const uint8_t* code, size_t size, bool is64) {
    std::vector<uint64_t> starts;
    const uint8_t prolog32[] = {0x55, 0x8B, 0xEC};
    const uint8_t prolog64[] = {0x55, 0x48, 0x89, 0xE5};

    for (size_t i = 0; i < size; ++i) {
        if (is64) {
            if (i + 4 <= size && memcmp(code + i, prolog64, 4) == 0) {
                starts.push_back(i);
            }
            // Prologues x64 fréquents sans frame pointer : sub rsp, imm8/imm32, push rbx/push rsi/push rdi...
            if (i + 4 <= size && code[i] == 0x48 && code[i + 1] == 0x83 && code[i + 2] == 0xEC) starts.push_back(i);
            if (i + 7 <= size && code[i] == 0x48 && code[i + 1] == 0x81 && code[i + 2] == 0xEC) starts.push_back(i);
            if (i + 2 <= size && code[i] >= 0x53 && code[i] <= 0x57) {
                if (i + 5 <= size && code[i + 1] == 0x48 && (code[i + 2] == 0x83 || code[i + 2] == 0x81) && code[i + 3] == 0xEC) starts.push_back(i);
            }
        } else {
            if (i + 3 <= size && memcmp(code + i, prolog32, 3) == 0) {
                starts.push_back(i);
            }
        }
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    return starts;
}

static std::vector<uint64_t> RuntimeFunctionStartsForSection(const PeInfo& pi, const SectionInfo& sec, size_t readableSize) {
    std::vector<uint64_t> starts;
    if (!pi.is64 || pi.runtimeFunctions.empty()) return starts;
    uint32_t secStart = sec.va;
    uint32_t secEnd = sec.va + (uint32_t)std::min<uint64_t>((uint64_t)readableSize, (uint64_t)std::max<uint32_t>(sec.vs, sec.rawSize));
    if (secEnd <= secStart) secEnd = sec.va + std::max<uint32_t>(sec.vs, sec.rawSize);
    for (const auto& rf : pi.runtimeFunctions) {
        if (rf.beginRva >= secStart && rf.beginRva < secEnd) {
            uint64_t off = (uint64_t)rf.beginRva - secStart;
            if (off < readableSize) starts.push_back(off);
        }
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    return starts;
}

static void MergeUniqueStarts(std::vector<uint64_t>& dst, const std::vector<uint64_t>& add) {
    dst.insert(dst.end(), add.begin(), add.end());
    std::sort(dst.begin(), dst.end());
    dst.erase(std::unique(dst.begin(), dst.end()), dst.end());
}



// Déclarations anticipées utilisées par l'export .pdata/unwind V16.
static std::wstring SanitizeFileNamePart(std::wstring s);
static bool GetOutputDirChecked(std::wstring& dir, std::wstring& err);
static bool WriteUtf8TextFile(const std::wstring& filePath, const std::wstring& content, bool writeBom);

// Déclarations anticipées pour les fonctions de détection de packer
static bool ContainsAsciiInsensitive(const std::vector<uint8_t>& data, const char* needle);
static bool DetectPackerBySignatures(const uint8_t* data, size_t size, std::wstring& name);


static std::vector<RuntimeFunctionInfo> RuntimeFunctionsForSection(const PeInfo& pi, const SectionInfo& sec, size_t readableSize) {
    std::vector<RuntimeFunctionInfo> out;
    if (!pi.is64 || pi.runtimeFunctions.empty()) return out;
    uint32_t secStart = sec.va;
    uint64_t readableEnd64 = (uint64_t)sec.va + std::min<uint64_t>((uint64_t)readableSize, (uint64_t)std::max<uint32_t>(sec.vs, sec.rawSize));
    uint32_t secEnd = readableEnd64 > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)readableEnd64;
    if (secEnd <= secStart) secEnd = sec.va + std::max<uint32_t>(sec.vs, sec.rawSize);
    for (const auto& rf : pi.runtimeFunctions) {
        if (rf.beginRva >= secStart && rf.beginRva < secEnd && rf.endRva > rf.beginRva) {
            uint64_t off = (uint64_t)rf.beginRva - secStart;
            uint64_t endOff = (uint64_t)rf.endRva - secStart;
            if (off < readableSize) {
                RuntimeFunctionInfo copy = rf;
                if (endOff > readableSize) copy.endRva = sec.va + (uint32_t)readableSize;
                out.push_back(copy);
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const RuntimeFunctionInfo& a, const RuntimeFunctionInfo& b) {
        if (a.beginRva != b.beginRva) return a.beginRva < b.beginRva;
        return a.endRva < b.endRva;
    });
    out.erase(std::unique(out.begin(), out.end(), [](const RuntimeFunctionInfo& a, const RuntimeFunctionInfo& b) {
        return a.beginRva == b.beginRva && a.endRva == b.endRva;
    }), out.end());
    return out;
}

static std::wstring GenerateRuntimeFunctionIndexCsv(const std::vector<RuntimeFunctionInfo>& ranges) {
    std::wstringstream ss;
    ss << L"index,begin_rva,end_rva,size,unwind_rva,begin_va,end_va\r\n";
    size_t idx = 0;
    for (const auto& rf : ranges) {
        ss << idx++ << L"," << Hex64(rf.beginRva, 8) << L"," << Hex64(rf.endRva, 8) << L"," << Dec((uint64_t)(rf.endRva - rf.beginRva))
           << L"," << Hex64(rf.unwindRva, 8) << L"," << Hex64(rf.beginVa, 16) << L"," << Hex64(rf.endVa, 16) << L"\r\n";
        if (idx >= ZC_MAX_FUNCTION_INDEX_EXPORT) {
            ss << L"# index truncated for report safety\r\n";
            break;
        }
    }
    return ss.str();
}

static bool ExportRuntimeFunctionIndex(const std::wstring& sectionName, const std::vector<RuntimeFunctionInfo>& ranges) {
    if (ranges.empty()) return false;
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) { AppendLog(L"[ERREUR] " + err); return false; }
    std::wstring baseName = SanitizeFileNamePart(sectionName);
    bool ok = WriteUtf8TextFile(dir + L"\\" + baseName + L"_pdata_functions.csv", GenerateRuntimeFunctionIndexCsv(ranges), false);
    if (ok) AppendLog(L"[OK] Index .pdata/unwind exporté : " + baseName + L"_pdata_functions.csv");
    return ok;
}

static bool GenerateX64dbgScript(const std::wstring& outputDir) {
    std::wstring scriptPath = outputDir + L"\\zenncomp_dump.dp64";
    std::wstringstream script;
    script << L"// Script ZennComp pour x64dbg - Dump mémoire après déchiffrement\n";
    script << L"// Utiliser avec ScyllaHide ou simplement breakpoints sur VirtualAlloc\n";
    script << L"\n";
    script << L"bp kernel32.VirtualAlloc\n";
    script << L"bp kernel32.VirtualProtect\n";
    script << L"bp ntdll.NtProtectVirtualMemory\n";
    script << L"bp ntdll.NtWriteVirtualMemory\n";
    script << L"\n";
    script << L"run\n";
    script << L"\n";
    script << L"// Après avoir atteint un breakpoint, vous pouvez dumper la mémoire avec Scylla\n";
    script << L"// Exemple : dump \"C:\\dump.bin\", 0x140000000, 0x1000000\n";
    script << L"\n";
    script << L"// Pour utiliser Scylla, activer le plugin, choisir le processus, cliquer sur Dump\n";
    script << L"// Puis utiliser le bouton Fix Dump pour reconstruire l'IAT\n";
    return WriteUtf8TextFile(scriptPath, script.str(), false);
}

static std::map<uint64_t, std::wstring> BuildDisassemblyByRuntimeFunctions(const uint8_t* sectionBytes,
                                                                           size_t sectionSize,
                                                                           uint64_t sectionBase,
                                                                           uint32_t sectionRva,
                                                                           bool is64,
                                                                           const std::vector<RuntimeFunctionInfo>& ranges,
                                                                           size_t maxInstructions = ZC_MAX_RECURSIVE_INSTRUCTIONS,
                                                                           int timeoutSeconds = ZC_RECURSIVE_TIMEOUT_SECONDS) {
    std::map<uint64_t, std::wstring> merged;
    if (!sectionBytes || sectionSize == 0 || ranges.empty()) return merged;
    auto startTime = std::chrono::steady_clock::now();
    size_t processed = 0;
    for (const auto& rf : ranges) {
        if (merged.size() >= maxInstructions) break;
        if (timeoutSeconds > 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() >= timeoutSeconds) break;
        }
        if (rf.endRva <= rf.beginRva || rf.beginRva < sectionRva) continue;
        uint64_t off64 = (uint64_t)rf.beginRva - (uint64_t)sectionRva;
        uint64_t end64 = (uint64_t)rf.endRva - (uint64_t)sectionRva;
        if (off64 >= sectionSize || end64 <= off64) continue;
        size_t off = (size_t)off64;
        size_t fsize = (size_t)std::min<uint64_t>(end64 - off64, (uint64_t)sectionSize - off64);
        if (fsize == 0) continue;
        uint64_t fbase = sectionBase + off;
        auto one = BuildDisassembly(sectionBytes + off, fsize, fbase, is64, maxInstructions - merged.size(), timeoutSeconds);
        merged.insert(one.begin(), one.end());
        processed++;
        if ((processed % 512) == 0) {
            AppendLog(L"[INFO] .pdata/unwind : " + Dec(processed) + L" fonctions analysées, " + Dec(merged.size()) + L" instructions.");
        }
    }
    return merged;
}

// --------------------------- Décompression UPX automatique ---------------------------
static bool IsUPXPresent() {
    wchar_t path[MAX_PATH];
    if (GetEnvironmentVariableW(L"PATH", path, MAX_PATH) == 0) return false;
    std::wstring pathStr = path;
    size_t pos = 0;
    while ((pos = pathStr.find(L';', pos)) != std::wstring::npos) {
        std::wstring dir = pathStr.substr(0, pos);
        std::wstring full = dir + L"\\upx.exe";
        if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
        pos++;
    }
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir = exePath;
    size_t lastSlash = exeDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) exeDir = exeDir.substr(0, lastSlash + 1);
    std::wstring localUpx = exeDir + L"upx.exe";
    return GetFileAttributesW(localUpx.c_str()) != INVALID_FILE_ATTRIBUTES;
}


static bool BufferContainsAsciiNoCase(const std::vector<uint8_t>& data, const char* needle) {
    if (!needle || !*needle || data.empty()) return false;
    size_t n = strlen(needle);
    if (n > data.size()) return false;
    for (size_t i = 0; i + n <= data.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < n; ++j) {
            unsigned char a = data[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

static bool LooksLikeUPXPackedFile(const std::vector<uint8_t>& data) {
    return BufferContainsAsciiNoCase(data, "UPX!") ||
           BufferContainsAsciiNoCase(data, "UPX0") ||
           BufferContainsAsciiNoCase(data, "UPX1") ||
           BufferContainsAsciiNoCase(data, "UPX2");
}

static bool UnpackUPX() {
    if (g_targetPath.empty() || g_file.empty()) {
        AppendLog(L"[ERREUR] Aucun fichier chargé.");
        return false;
    }

    if (!IsUPXPresent()) {
        AppendLog(L"[ERREUR] upx.exe introuvable. Téléchargez UPX et placez-le dans le PATH ou à côté de ZennComp.exe.");
        MessageBoxW(g_hWnd, L"upx.exe est requis pour la décompression.\nTéléchargez UPX depuis https://upx.github.io/ et placez-le dans le PATH ou à côté de ZennComp.exe.", L"ZennComp", MB_ICONERROR);
        return false;
    }

    if (!LooksLikeUPXPackedFile(g_file)) {
        AppendLog(L"[INFO] Aucun marqueur UPX détecté : décompression UPX ignorée proprement.");
        MessageBoxW(g_hWnd, L"Ce fichier ne semble pas compressé avec UPX.\nLa décompression UPX est ignorée pour éviter une fausse erreur.", L"ZennComp", MB_ICONINFORMATION);
        return false;
    }

    std::wstring srcDir = g_targetPath;
    size_t lastSlash = srcDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        srcDir = srcDir.substr(0, lastSlash + 1);
    } else {
        srcDir = L".\\";
    }
    std::wstring baseName = BaseName(g_targetPath);
    size_t ext = baseName.find_last_of(L'.');
    if (ext != std::wstring::npos) {
        baseName = baseName.substr(0, ext);
    }
    std::wstring outputFile = srcDir + baseName + L"_unpacked.exe";

    DeleteFileW(outputFile.c_str());

    wchar_t tempPath[MAX_PATH];
    wchar_t tempFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"ZUP", 0, tempFile);
    std::wstring inputFile = tempFile;

    HANDLE hIn = CreateFileW(inputFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) {
        AppendLog(L"[ERREUR] Impossible de créer le fichier temporaire d'entrée.");
        return false;
    }
    DWORD written = 0;
    WriteFile(hIn, g_file.data(), (DWORD)g_file.size(), &written, nullptr);
    CloseHandle(hIn);

    wchar_t cmdLine[4096];
    wsprintfW(cmdLine, L"upx.exe -d -o \"%s\" \"%s\"", outputFile.c_str(), inputFile.c_str());

    AppendLog(L"[INFO] Décompression UPX en cours...");
    SetStatus(L"Décompression UPX...");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        AppendLog(L"[ERREUR] Impossible de lancer upx.exe. Code Win32=" + Dec(GetLastError()));
        DeleteFileW(inputFile.c_str());
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileW(inputFile.c_str());

    if (exitCode != 0) {
        AppendLog(L"[ERREUR] UPX a échoué avec le code " + Dec(exitCode) + L". Le fichier n'est peut-être pas compressé ou est corrompu.");
        DeleteFileW(outputFile.c_str());
        return false;
    }

    std::wstring err;
    std::vector<uint8_t> newData;
    if (!ReadFileBytes(outputFile, newData, err)) {
        AppendLog(L"[ERREUR] Impossible de lire le fichier décompressé : " + err);
        DeleteFileW(outputFile.c_str());
        return false;
    }

    g_file.swap(newData);
    g_targetPath = outputFile;
    AppendLog(L"[OK] Décompression réussie. Nouvelle taille : " + Dec(g_file.size()) + L" octets");
    AppendLog(L"[OK] Fichier décompressé : " + outputFile);
    SetStatus(L"Fichier décompressé - " + BaseName(outputFile));
    return true;
}

// --------------------------- Gestion des exports (chemin absolu) ---------------------------
static std::wstring SanitizeFileNamePart(std::wstring s) {
    if (s.empty()) return L"section";
    const std::wstring invalid = L"<>:\"/\\|?*";
    for (wchar_t& c : s) {
        if (c < 32 || invalid.find(c) != std::wstring::npos) {
            c = L'_';
        }
    }
    while (!s.empty() && (s.back() == L'.' || s.back() == L' ')) {
        s.pop_back();
    }
    if (s.empty()) s = L"section";
    if (s.size() > 80) s.resize(80);
    return s;
}

static bool EnsureDirectoryExists(const std::wstring& dir, std::wstring& err) {
    if (dir.empty()) {
        err = L"Chemin du dossier de sortie vide.";
        return false;
    }

    DWORD attrs = GetFileAttributesW(dir.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) return true;
        err = L"Le chemin existe mais n'est pas un dossier : " + dir;
        return false;
    }

    if (CreateDirectoryW(dir.c_str(), nullptr)) {
        return true;
    }

    DWORD code = GetLastError();
    if (code == ERROR_ALREADY_EXISTS) {
        attrs = GetFileAttributesW(dir.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return true;
    }

    err = L"CreateDirectoryW a echoue pour " + dir + L". Code Win32=" + Dec(code);
    return false;
}

static bool GetOutputDirChecked(std::wstring& dir, std::wstring& err) {
    std::wstring base = g_targetPath;
    size_t lastSlash = base.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        base = base.substr(0, lastSlash + 1);
    } else {
        base = L".\\";
    }

    std::wstring name = BaseName(g_targetPath);
    size_t ext = name.find_last_of(L'.');
    if (ext != std::wstring::npos) name = name.substr(0, ext);
    name = SanitizeFileNamePart(name);

    dir = base + name + L"_decompile";
    bool ok = EnsureDirectoryExists(dir, err);
    if (ok) g_lastOutputDir = dir;
    return ok;
}

static std::wstring GetOutputDir() {
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) {
        AppendLog(L"[ERREUR] " + err);
    }
    return dir;
}

static bool WriteUtf8TextFile(const std::wstring& filePath, const std::wstring& content, bool writeBom = true) {
    HANDLE h = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        AppendLog(L"[ERREUR] Impossible de creer " + filePath + L". Code Win32=" + Dec(GetLastError()));
        return false;
    }

    DWORD wr = 0;
    bool ok = true;
    if (writeBom) {
        const uint8_t bom[3] = {0xEF, 0xBB, 0xBF};
        ok = WriteFile(h, bom, 3, &wr, nullptr) && wr == 3;
    }

    std::string utf8 = WideToUtf8(content);
    if (ok && !utf8.empty()) {
        ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wr, nullptr) && wr == utf8.size();
    }

    DWORD lastErr = ok ? 0 : GetLastError();
    CloseHandle(h);

    if (!ok) {
        AppendLog(L"[ERREUR] Ecriture incomplete ou impossible : " + filePath + L". Code Win32=" + Dec(lastErr));
        DeleteFileW(filePath.c_str());
        return false;
    }
    return true;
}

static bool ExportTextToOutputFile(const std::wstring& fileName, const std::wstring& content) {
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) {
        AppendLog(L"[ERREUR] " + err);
        return false;
    }

    std::wstring filePath = dir + L"\\" + SanitizeFileNamePart(fileName);
    if (!WriteUtf8TextFile(filePath, content)) {
        return false;
    }

    AppendLog(L"[OK] Exporté : " + filePath);
    return true;
}

static bool WriteRuntimeSupportFiles(const std::wstring& dir) {
    std::wstring header = LR"ZCH(#ifndef ZENNCOMP_RUNTIME_H
#define ZENNCOMP_RUNTIME_H
#include <stdint.h>
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
static void ZC_LOG2(const char* op, const char* a, const char* b) { (void)op; (void)a; (void)b; }
static void ZC_LOG1(const char* op, const char* a) { (void)op; (void)a; }
static void ZC_MOV(const char* a,const char* b){ZC_LOG2("mov",a,b);}
static void ZC_EXTEND(const char* a,const char* b){ZC_LOG2("extend",a,b);}
static void ZC_LEA(const char* a,const char* b){ZC_LOG2("lea",a,b);}
static void ZC_XOR(const char* a,const char* b){ZC_LOG2("xor",a,b);}
static void ZC_ADD(const char* a,const char* b){ZC_LOG2("add",a,b);}
static void ZC_SUB(const char* a,const char* b){ZC_LOG2("sub",a,b);}
static void ZC_AND(const char* a,const char* b){ZC_LOG2("and",a,b);}
static void ZC_OR(const char* a,const char* b){ZC_LOG2("or",a,b);}
static void ZC_CMP(const char* a,const char* b){ZC_LOG2("cmp",a,b);}
static void ZC_TEST(const char* a,const char* b){ZC_LOG2("test",a,b);}
static void ZC_PUSH(const char* a){ZC_LOG1("push",a);}
static void ZC_POP(const char* a){ZC_LOG1("pop",a);}
static void ZC_INC(const char* a){ZC_LOG1("inc",a);}
static void ZC_DEC(const char* a){ZC_LOG1("dec",a);}
static void ZC_CALL(const char* a){ZC_LOG1("call",a);}
static void ZC_JMP(const char* a){ZC_LOG1("jmp",a);}
static void ZC_JCC(const char* c,const char* a){ZC_LOG2(c,a,"");}
static void ZC_OP(const char* op,const char* a){ZC_LOG2(op,a,"");}
static void ZC_DB(const char* a){ZC_LOG1("db",a);}
static void ZC_NOP(void){}
static void ZC_TRAP(void){}
static void ZC_LEAVE(void){}
#ifdef __cplusplus
}
#endif
#endif
)ZCH";

    std::wstring driver = LR"ZCD(#include "zenncomp_runtime.h"
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    puts("ZennComp rebuilt analysis stub - not the original binary.");
    return 0;
}
)ZCD";

    bool ok1 = WriteUtf8TextFile(dir + L"\\zenncomp_runtime.h", header);
    bool ok2 = WriteUtf8TextFile(dir + L"\\zenncomp_driver.c", driver);
    if (ok1 && ok2) {
        AppendLog(L"[OK] Runtime de recompilation écrit dans : " + dir);
    }
    return ok1 && ok2;
}

static bool ExportPseudoCToFile(const std::wstring& pseudo, const std::wstring& sectionName, const std::wstring& suffix = L"_decompiled") {
    if (pseudo.empty()) {
        AppendLog(L"[WARN] Pseudo-C vide pour " + sectionName + L" : export ignore.");
        return false;
    }

    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) {
        AppendLog(L"[ERREUR] " + err);
        return false;
    }

    WriteRuntimeSupportFiles(dir);

    std::wstring safeName = SanitizeFileNamePart(sectionName) + suffix + L".c";
    std::wstring filePath = dir + L"\\" + safeName;
    if (!WriteUtf8TextFile(filePath, pseudo)) {
        return false;
    }

    AppendLog(L"[OK] Pseudo-C exporté : " + filePath);
    return true;
}

static void ExportDisassemblyToFile(const std::map<uint64_t, std::wstring>& disasm, const std::wstring& sectionName, const std::wstring& suffix = L"") {
    if (disasm.empty()) {
        AppendLog(L"[WARN] Désassemblage vide pour " + sectionName + L" : export ASM ignore.");
        return;
    }

    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) {
        AppendLog(L"[ERREUR] " + err);
        return;
    }

    std::wstring filePath = dir + L"\\" + SanitizeFileNamePart(sectionName) + suffix + L".asm";
    std::wstringstream ss;
    for (const auto& [addr, line] : disasm) {
        ss << line << L"\r\n";
    }

    if (WriteUtf8TextFile(filePath, ss.str())) {
        AppendLog(L"[OK] Exporté : " + filePath);
    }
}

struct SectionBytes {
    const uint8_t* data = nullptr;
    size_t size = 0;
    uint32_t fileOffset = 0;
    bool virtualOnly = false;
    bool truncated = false;
    std::vector<uint8_t> owned;
};

static bool ResolveSectionBytes(const SectionInfo& sec, SectionBytes& out, std::wstring& reason) {
    out = SectionBytes{};

    uint64_t wanted = sec.rawSize ? (uint64_t)sec.rawSize : (uint64_t)sec.vs;
    if (wanted == 0) {
        reason = L"rawSize=0 et virtualSize=0";
        return false;
    }

    size_t capped = (size_t)std::min<uint64_t>(wanted, ZC_MAX_SECTION_ANALYZE_BYTES);
    out.truncated = wanted > capped;

    if (sec.rawSize > 0) {
        if (sec.raw >= g_file.size()) {
            reason = L"PointerToRawData hors fichier : RAW=" + Hex64(sec.raw, 8) + L", taille fichier=" + Dec(g_file.size());
            return false;
        }

        size_t available = g_file.size() - sec.raw;
        size_t readable = std::min<size_t>(std::min<size_t>((size_t)sec.rawSize, available), capped);
        if (readable == 0) {
            reason = L"section sans octets lisibles sur disque";
            return false;
        }

        out.data = g_file.data() + sec.raw;
        out.size = readable;
        out.fileOffset = sec.raw;
        if (readable < sec.rawSize) out.truncated = true;
        return true;
    }

    // Section présente uniquement en mémoire au chargement PE : le contenu disque est absent.
    // Pour éviter un échec silencieux, on matérialise la zone virtuelle par des zéros.
    out.owned.assign(capped, 0);
    out.data = out.owned.data();
    out.size = out.owned.size();
    out.fileOffset = sec.raw;
    out.virtualOnly = true;
    return true;
}


static std::wstring GenerateDataArraySource(const std::wstring& symbolBase,
                                           const uint8_t* data,
                                           size_t size,
                                           bool cppMode) {
    std::wstring sym = SanitizeIdentifier(symbolBase);
    std::wstringstream out;
    if (cppMode) {
        out << L"#include <cstdint>\n#include <cstddef>\n\n";
        out << L"namespace zenncomp_rebuild {\n";
        out << L"alignas(16) static const std::uint8_t " << sym << L"_data[] = {\n";
    } else {
        out << L"#include <stdint.h>\n#include <stddef.h>\n\n";
        out << L"static const uint8_t " << sym << L"_data[] = {\n";
    }

    const size_t maxBytes = std::min<size_t>(size, 1024 * 1024); // limite raisonnable pour éviter des sources énormes
    for (size_t i = 0; i < maxBytes; ++i) {
        if (i % 16 == 0) out << L"    ";
        out << Hex64(data[i], 2);
        if (i + 1 < maxBytes) out << L", ";
        if (i % 16 == 15 || i + 1 == maxBytes) out << L"\n";
    }
    if (size > maxBytes) {
        out << L"    /* données tronquées : " << Dec(size - maxBytes) << L" octets non intégrés */\n";
    }

    if (cppMode) {
        out << L"};\n";
        out << L"static constexpr std::size_t " << sym << L"_size = sizeof(" << sym << L"_data);\n";
        out << L"} // namespace zenncomp_rebuild\n";
    } else {
        out << L"};\n";
        out << L"static const size_t " << sym << L"_size = sizeof(" << sym << L"_data);\n";
    }
    return out.str();
}

static bool ExportSectionBytesAsDataSource(const SectionInfo& sec, const SectionBytes& bytes, bool cppMode) {
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) {
        AppendLog(L"[ERREUR] " + err);
        return false;
    }

    std::wstring base = SanitizeFileNamePart(sec.name);
    std::wstring ext = cppMode ? L".cpp" : L".c";
    std::wstring outPath = dir + L"\\" + base + L"_data" + ext;
    std::wstring symbol = L"zc_" + SanitizeIdentifier(sec.name);
    std::wstring content = GenerateDataArraySource(symbol, bytes.data, bytes.size, cppMode);
    if (!WriteUtf8TextFile(outPath, NormalizeTextForFile(content))) return false;
    AppendLog(L"[OK] Section non-code exportée en données : " + outPath);
    return true;
}

static void ExportStringsFromSection(const SectionInfo& sec, const SectionBytes& bytes, const std::wstring& outputDir) {
    if (bytes.size == 0) return;
    std::wstring base = SanitizeFileNamePart(sec.name);
    std::wstring outPath = outputDir + L"\\" + base + L"_strings.txt";
    std::wstringstream ss;
    ss << L"# Chaînes extraites de la section " << sec.name << L"\r\n\r\n";
    // ASCII
    std::string cur;
    for (size_t i = 0; i < bytes.size; ++i) {
        if (IsPrintableAscii(bytes.data[i])) {
            cur.push_back((char)bytes.data[i]);
        } else {
            if (cur.size() >= 5) {
                ss << L"ASCII @ 0x" << Hex64(i - cur.size(), 8) << L": " << Utf8ToWide(cur) << L"\r\n";
            }
            cur.clear();
        }
    }
    if (cur.size() >= 5) {
        ss << L"ASCII @ 0x" << Hex64(bytes.size - cur.size(), 8) << L": " << Utf8ToWide(cur) << L"\r\n";
    }
    // UTF-16
    std::wstring wcur;
    for (size_t i = 0; i + 1 < bytes.size; i += 2) {
        uint16_t ch = (uint16_t)bytes.data[i] | ((uint16_t)bytes.data[i+1] << 8);
        if (ch >= 32 && ch <= 126) {
            wcur.push_back((wchar_t)ch);
        } else {
            if (wcur.size() >= 5) {
                ss << L"UTF-16 @ 0x" << Hex64(i - wcur.size()*2, 8) << L": " << wcur << L"\r\n";
            }
            wcur.clear();
        }
    }
    if (wcur.size() >= 5) {
        ss << L"UTF-16 @ 0x" << Hex64(bytes.size - wcur.size()*2, 8) << L": " << wcur << L"\r\n";
    }
    WriteUtf8TextFile(outPath, ss.str(), true);
    AppendLog(L"[OK] Chaînes exportées : " + outPath);
}

static bool LooksLikeDataDisassembly(const std::map<uint64_t, std::wstring>& disasm) {
    if (disasm.empty()) return false;
    size_t db = 0;
    size_t total = 0;
    for (const auto& kv : disasm) {
        std::wstring mn = MnemonicFromAsmText(StripAddressFromDisasmLine(kv.second));
        if (mn.empty()) continue;
        total++;
        if (mn == L"db") db++;
    }
    return total > 0 && (db * 100 / total) >= 55;
}


static std::wstring DotEscape(std::wstring s) {
    ReplaceAllW(s, L"\\", L"\\\\");
    ReplaceAllW(s, L"\"", L"\\\"");
    ReplaceAllW(s, L"\r", L" ");
    ReplaceAllW(s, L"\n", L" ");
    return s;
}

static std::wstring GenerateCfgDot(const std::wstring& sectionName, const std::vector<BasicBlock>& blocks) {
    std::wstringstream dot;
    dot << L"digraph ZennComp_CFG {\n";
    dot << L"  graph [label=\"ZennComp CFG - " << DotEscape(sectionName) << L"\", labelloc=t, fontsize=18];\n";
    dot << L"  node [shape=box, fontname=\"Consolas\", fontsize=9];\n";
    for (const auto& b : blocks) {
        dot << L"  n" << std::uppercase << std::hex << b.start << L" [label=\"" << DotEscape(Hex64(b.start, 8) + L"\\n" + b.type + L"\\n" + Dec(b.instructions.size()) + L" instr") << L"\"];\n";
    }
    for (const auto& b : blocks) {
        for (uint64_t succ : b.successors) {
            dot << L"  n" << std::uppercase << std::hex << b.start << L" -> n" << succ;
            if (b.fallthrough && succ == b.successors.back()) dot << L" [style=dashed,label=\"fallthrough\"]";
            dot << L";\n";
        }
    }
    dot << L"}\n";
    return dot.str();
}

static std::wstring GenerateCallGraphDot(const std::wstring& sectionName, const std::vector<BasicBlock>& blocks, const std::vector<ThunkInfo>& thunks) {
    std::wstringstream dot;
    dot << L"digraph ZennComp_CallGraph {\n";
    dot << L"  graph [label=\"ZennComp Call Graph - " << DotEscape(sectionName) << L"\", labelloc=t, fontsize=18];\n";
    dot << L"  node [shape=ellipse, fontname=\"Consolas\"];\n";
    std::set<std::pair<uint64_t,uint64_t>> edges;
    for (const auto& b : blocks) for (uint64_t c : b.calls) edges.insert({b.start, c});
    if (edges.empty() && thunks.empty()) dot << L"  section [label=\"Aucun appel direct immédiat détecté\"];\n";
    for (const auto& e : edges) {
        dot << L"  sub_" << std::uppercase << std::hex << e.first << L" -> sub_" << e.second << L";\n";
    }
    for (const auto& t : thunks) {
        dot << L"  sub_" << std::uppercase << std::hex << t.va << L" -> \"" << DotEscape(t.importName) << L"\" [label=\"IAT thunk\"];\n";
    }
    dot << L"}\n";
    return dot.str();
}


static CodeQualityMetrics AssessCodeQuality(const uint8_t* bytes,
                                            size_t size,
                                            const std::map<uint64_t, std::wstring>& disasm,
                                            const std::vector<uint64_t>& funcs,
                                            bool executable) {
    CodeQualityMetrics q;
    q.entropy = bytes && size ? Entropy(bytes, size) : 0.0;
    for (const auto& kv : disasm) {
        std::wstring mn = MnemonicFromAsmText(StripAddressFromDisasmLine(kv.second));
        if (mn.empty()) continue;
        q.totalInstructions++;
        if (mn == L"db") q.dbInstructions++;
        if (mn == L"call") q.callCount++;
        if (mn == L"jmp" || IsConditionalJumpMnemonic(mn)) q.branchCount++;
        if (mn == L"ret" || mn == L"retf") q.retCount++;
    }
    q.dbRatio = q.totalInstructions ? (double)q.dbInstructions / (double)q.totalInstructions : 0.0;

    bool highEntropy = q.entropy >= ZC_PACKED_ENTROPY_THRESHOLD;
    bool veryHighEntropy = q.entropy >= ZC_STRONG_PACKED_ENTROPY_THRESHOLD;
    bool noFunctionShape = executable && funcs.empty() && q.retCount == 0 && q.callCount == 0;
    bool tooManyDb = q.dbRatio >= ZC_DB_RATIO_SUSPICIOUS;
    bool hasReliableFunctionBoundaries = executable && !funcs.empty();
    q.probablyPackedOrEncrypted = !hasReliableFunctionBoundaries && ((veryHighEntropy && (tooManyDb || noFunctionShape)) || (highEntropy && tooManyDb));

    if (q.probablyPackedOrEncrypted) {
        q.verdict = L"packed/chiffré/obfusqué probable : désassemblage non fiable, extraction/émulation requise";
    } else if (hasReliableFunctionBoundaries && highEntropy) {
        q.verdict = L"code protégé/optimisé mais bornes de fonctions fiables disponibles (.pdata/prologues)";
    } else if (highEntropy) {
        q.verdict = L"entropie élevée : code possiblement compressé ou fortement optimisé";
    } else if (tooManyDb) {
        q.verdict = L"qualité faible : beaucoup d'octets non décodés";
    } else {
        q.verdict = L"code exploitable pour CFG/pseudo-C";
    }
    return q;
}

static std::vector<IndirectCallInfo> DetectIndirectCalls(const std::map<uint64_t, std::wstring>& disasm,
                                                         const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<IndirectCallInfo> out;
    for (const auto& kv : disasm) {
        std::wstring asmText = StripAddressFromDisasmLine(kv.second);
        std::wstring mn = MnemonicFromAsmText(asmText);
        if (mn != L"call" && mn != L"jmp") continue;
        std::wstring ops = OperandsFromAsmText(asmText);
        uint64_t imm = ParseLastHexImmediate(ops);
        bool direct = imm != 0 && ops.find(L"[") == std::wstring::npos;
        if (direct) continue;
        IndirectCallInfo ic;
        ic.va = kv.first;
        ic.kind = mn;
        ic.operand = ops;
        if (imm && iatMap.count(imm)) ic.resolution = L"IAT -> " + iatMap.at(imm);
        else if (ops.find(L"[") != std::wstring::npos && (ops.find(L"*") != std::wstring::npos || LowerW(ops).find(L"rip") != std::wstring::npos)) ic.resolution = L"table/jump/call indirect candidat";
        else ic.resolution = L"cible indirecte non résolue";
        out.push_back(ic);
    }
    return out;
}

static std::vector<SsaFact> BuildSsaFacts(const std::vector<BasicBlock>& blocks) {
    std::vector<SsaFact> facts;
    std::map<std::wstring, unsigned> version;
    for (const auto& b : blocks) {
        for (const auto& instr : b.instructions) {
            std::wstring asmText = StripAddressFromDisasmLine(instr);
            auto ops = SplitOperands(OperandsFromAsmText(asmText));
            std::wstring mn = MnemonicFromAsmText(asmText);
            if (ops.empty()) continue;
            if (mn == L"mov" || mn == L"movzx" || mn == L"movsx" || mn == L"lea" || mn == L"add" || mn == L"sub" || mn == L"xor" || mn == L"and" || mn == L"or" || mn == L"imul") {
                std::wstring lhs = StripAsmTrailingComment(SanitizeCOperand(ops[0]));
                if (lhs.empty() || lhs.find(L"[") != std::wstring::npos) continue;
                unsigned v = ++version[lhs];
                SsaFact f;
                f.va = InstructionAddressFromLine(instr);
                f.lhs = lhs + L"_" + Dec(v);
                f.version = v;
                f.rhs = asmText;
                facts.push_back(f);
                if (facts.size() >= 5000) return facts;
            }
        }
    }
    return facts;
}

static std::vector<TypeHint> RecoverTypeHints(const std::vector<BasicBlock>& blocks,
                                              const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<TypeHint> hints;
    std::set<std::wstring> seen;
    auto add = [&](const std::wstring& sym, const std::wstring& ty, const std::wstring& ev) {
        std::wstring key = sym + L"|" + ty + L"|" + ev;
        if (seen.insert(key).second) hints.push_back(TypeHint{sym, ty, ev});
    };
    for (const auto& kv : iatMap) {
        std::wstring low = LowerW(kv.second);
        if (low.find(L"createfile") != std::wstring::npos || low.find(L"readfile") != std::wstring::npos || low.find(L"writefile") != std::wstring::npos) add(kv.second, L"HANDLE / buffer / DWORD", L"API Win32 fichier");
        if (low.find(L"reg") != std::wstring::npos) add(kv.second, L"HKEY / registry string", L"API registre");
        if (low.find(L"socket") != std::wstring::npos || low.find(L"internet") != std::wstring::npos || low.find(L"winhttp") != std::wstring::npos) add(kv.second, L"network handle / URL / socket", L"API réseau");
        if (low.find(L"bstr") != std::wstring::npos || low.find(L"ole") != std::wstring::npos || low.find(L"cocreate") != std::wstring::npos) add(kv.second, L"COM interface pointer", L"API COM/OLE");
    }
    for (const auto& b : blocks) {
        for (const auto& instr : b.instructions) {
            std::wstring a = LowerW(StripAddressFromDisasmLine(instr));
            if (a.find(L"[rcx+") != std::wstring::npos || a.find(L"[ecx+") != std::wstring::npos || a.find(L"[this+") != std::wstring::npos) add(L"this", L"class/struct pointer", L"accès mémoire relatif à this");
            if (a.find(L"vftable") != std::wstring::npos || a.find(L"vtable") != std::wstring::npos) add(L"vtable", L"C++ virtual table", L"symbole/chaîne vtable");
            if (hints.size() >= 1000) return hints;
        }
    }
    return hints;
}

static std::vector<CppClassHint> RecoverCppClassHints(const std::map<uint64_t, std::wstring>& disasm,
                                                      const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<CppClassHint> out;
    for (const auto& kv : disasm) {
        std::wstring a = LowerW(StripAddressFromDisasmLine(kv.second));
        if (a.find(L"[rcx]") != std::wstring::npos || a.find(L"[ecx]") != std::wstring::npos || a.find(L"vftable") != std::wstring::npos || a.find(L"vtable") != std::wstring::npos) {
            CppClassHint h; h.va = kv.first; h.name = L"class_candidate_" + Hex64(kv.first, 8); h.evidence = StripAddressFromDisasmLine(kv.second); out.push_back(h);
            if (out.size() >= 500) break;
        }
    }
    for (const auto& kv : iatMap) {
        std::wstring low = LowerW(kv.second);
        if (low.find(L"cxx") != std::wstring::npos || low.find(L"typeinfo") != std::wstring::npos || low.find(L"rtti") != std::wstring::npos) {
            CppClassHint h; h.va = kv.first; h.name = L"msvc_cpp_runtime"; h.evidence = kv.second; out.push_back(h);
        }
    }
    return out;
}

static std::vector<ExceptionHint> RecoverExceptionHints(const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<ExceptionHint> out;
    std::set<std::wstring> seen;
    for (const auto& kv : iatMap) {
        std::wstring low = LowerW(kv.second);
        if (low.find(L"cxxframehandler") != std::wstring::npos || low.find(L"except_handler") != std::wstring::npos || low.find(L"rtlunwind") != std::wstring::npos || low.find(L"raiseexception") != std::wstring::npos || low.find(L"setunhandledexceptionfilter") != std::wstring::npos) {
            if (seen.insert(kv.second).second) out.push_back(ExceptionHint{kv.second, L"IAT/import runtime exception"});
        }
    }
    return out;
}

static std::wstring GenerateDeepDecompilerReport(const std::map<uint64_t, std::wstring>& disasm,
                                                 const std::vector<BasicBlock>& blocks,
                                                 const std::vector<uint64_t>& funcs,
                                                 const std::map<uint64_t, std::wstring>& iatMap) {
    auto ssa = BuildSsaFacts(blocks);
    auto types = RecoverTypeHints(blocks, iatMap);
    auto classes = RecoverCppClassHints(disasm, iatMap);
    auto exceptions = RecoverExceptionHints(iatMap);
    auto indirects = DetectIndirectCalls(disasm, iatMap);
    std::wstringstream r;
    r << L"\r\n## Moteur V14 : CFG / SSA / Types / C++ / Exceptions / Indirects\r\n";
    r << L"- SSA facts construits : " << ssa.size() << L"\r\n";
    r << L"- Hints de types : " << types.size() << L"\r\n";
    r << L"- Hints classes/RTTI : " << classes.size() << L"\r\n";
    r << L"- Hints exceptions : " << exceptions.size() << L"\r\n";
    r << L"- Appels/sauts indirects : " << indirects.size() << L"\r\n";

    r << L"\r\n### SSA aperçu\r\n";
    if (ssa.empty()) r << L"- Aucun fait SSA exploitable.\r\n";
    for (size_t i = 0; i < ssa.size() && i < 200; ++i) r << L"- " << Hex64(ssa[i].va, 8) << L" : " << ssa[i].lhs << L" := `" << ssa[i].rhs << L"`\r\n";
    if (ssa.size() > 200) r << L"- ... SSA tronqué dans le rapport, analyse interne complète en mémoire.\r\n";

    r << L"\r\n### Types C/C++ inférés\r\n";
    if (types.empty()) r << L"- Aucun type haut niveau fiable inféré.\r\n";
    for (size_t i = 0; i < types.size() && i < 200; ++i) r << L"- " << types[i].symbol << L" => " << types[i].inferredType << L" (" << types[i].evidence << L")\r\n";

    r << L"\r\n### Classes / RTTI candidates\r\n";
    if (classes.empty()) r << L"- Aucun indice classe/RTTI évident.\r\n";
    for (size_t i = 0; i < classes.size() && i < 200; ++i) r << L"- " << Hex64(classes[i].va, 8) << L" : " << classes[i].name << L" (`" << classes[i].evidence << L"`)\r\n";

    r << L"\r\n### Exceptions\r\n";
    if (exceptions.empty()) r << L"- Aucun runtime d'exception évident via IAT.\r\n";
    for (const auto& e : exceptions) r << L"- " << e.handler << L" : " << e.evidence << L"\r\n";

    r << L"\r\n### Appels indirects / résolution partielle\r\n";
    if (indirects.empty()) r << L"- Aucun appel indirect évident.\r\n";
    for (size_t i = 0; i < indirects.size() && i < 300; ++i) r << L"- " << Hex64(indirects[i].va, 8) << L" : " << indirects[i].kind << L" `" << indirects[i].operand << L"` => " << indirects[i].resolution << L"\r\n";
    return r.str();
}

static bool ExportPackedTriageReport(const SectionInfo& sec,
                                     const SectionBytes& bytes,
                                     const CodeQualityMetrics& quality,
                                     const std::vector<uint64_t>& funcs,
                                     const std::map<uint64_t, std::wstring>& disasm) {
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) { AppendLog(L"[ERREUR] " + err); return false; }
    std::wstring base = SanitizeFileNamePart(sec.name);
    std::wstringstream r;
    r << L"# ZennComp V14 - triage section packed/chiffrée suspecte : " << sec.name << L"\r\n\r\n";
    r << L"- Taille analysée : " << bytes.size << L" octets\r\n";
    r << L"- Entropie : " << std::fixed << std::setprecision(3) << quality.entropy << L"\r\n";
    r << L"- Instructions décodées : " << quality.totalInstructions << L"\r\n";
    r << L"- Ratio DB/non décodé : " << std::fixed << std::setprecision(2) << (quality.dbRatio * 100.0) << L"%\r\n";
    r << L"- Prologues détectés : " << funcs.size() << L"\r\n";
    r << L"- Verdict : " << quality.verdict << L"\r\n\r\n";
    r << L"## Analyse\r\n";
    r << L"ZennComp évite volontairement de produire un faux pseudo-C lorsque la section ressemble à du code packé/chiffré.\r\n";
    r << L"La bonne stratégie est : identification packer/protecteur, récupération d'une image mémoire ou d'un dump légal, puis relance du CFG/SSA sur l'image déprotégée.\r\n";
    r << L"ZennComp ne tente pas de casser des clés, licences, DRM ou protections tierces : le module reste orienté audit, triage et préparation d'analyse.\r\n\r\n";
    r << L"## Aperçu désassemblage bruité\r\n";
    size_t shown = 0;
    for (const auto& kv : disasm) { r << L"- `" << kv.second << L"`\r\n"; if (++shown >= 200) break; }
    return WriteUtf8TextFile(dir + L"\\" + base + L"_packed_triage.md", r.str(), true);
}

// Procédure de la fenêtre de dialogue éthique
static LRESULT CALLBACK EthicsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Ajout des icônes
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP)));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));

        // Création des contrôles
        HWND hText = CreateWindowW(L"STATIC",
            L"ZennComp est un outil de rétro-ingénierie statique à usage éducatif et d'audit.\n\n"
            L"L'utilisateur est seul responsable de l'utilisation qu'il fait de cet outil.\n"
            L"Toute utilisation sur des logiciels dont vous n'êtes pas propriétaire ou sans autorisation explicite est interdite.\n"
            L"Respectez les lois en vigueur et les droits d'auteur.\n\n"
            L"Si cet outil vous est utile, vous pouvez soutenir son développement par un don :",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 10, 460, 150, hwnd, nullptr, g_hInst, nullptr);
        SendMessageW(hText, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        HWND hBtnDon = CreateWindowW(L"BUTTON", L"Faire un don PayPal",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            150, 180, 200, 30, hwnd, (HMENU)1002, g_hInst, nullptr);
        SendMessageW(hBtnDon, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        HWND hBtnClose = CreateWindowW(L"BUTTON", L"Fermer",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            200, 220, 100, 30, hwnd, (HMENU)IDOK, g_hInst, nullptr);
        SendMessageW(hBtnClose, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        return 0;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            DestroyWindow(hwnd);
            return 0;
        case 1002: // Bouton Don
            ShellExecuteW(hwnd, L"open",
                L"https://www.paypal.com/donate/?hosted_button_id=FSX7RHUT4BDRY",
                nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        break;
    }
    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowEthicsDialog(HWND hwndOwner) {
    const wchar_t* cls = L"ZennCompEthicsDialog";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.hInstance = g_hInst;
        wc.lpfnWndProc = EthicsWndProc;
        wc.lpszClassName = cls;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    HWND hDlg = CreateWindowExW(0, cls, L"Éthique et responsabilité",
                                WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 500, 300,
                                hwndOwner, nullptr, g_hInst, nullptr);
    if (!hDlg) return;

    // Rendre la fenêtre modale (désactiver le parent)
    EnableWindow(hwndOwner, FALSE);

    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    EnableWindow(hwndOwner, TRUE);
    SetForegroundWindow(hwndOwner);
}

static std::wstring GenerateAdvancedFunctionReport(const std::wstring& sectionName,
                                                   const std::map<uint64_t, std::wstring>& disasm,
                                                   const std::vector<BasicBlock>& blocks,
                                                   const std::vector<uint64_t>& funcs,
                                                   uint64_t sectionBase,
                                                   const std::map<uint64_t, std::wstring>& iatMap,
                                                   const std::vector<ThunkInfo>& thunks,
                                                   const std::vector<JumpTableInfo>& jumpTables) {
    size_t edges = 0, calls = 0, returns = 0, branches = 0, importCalls = 0;
    for (const auto& b : blocks) {
        edges += b.successors.size();
        calls += b.calls.size();
        importCalls += b.importCalls.size();
        if (b.type == L"return") returns++;
        if (b.type == L"condition" || b.type == L"jump") branches++;
    }
    std::wstringstream r;
    r << L"# ZennComp V16 Unwind-Aware Engine - rapport avancé section " << sectionName << L"\r\n\r\n";
    r << L"## Synthèse\r\n";
    r << L"- Instructions analysées : " << disasm.size() << L"\r\n";
    r << L"- Blocs de base CFG : " << blocks.size() << L"\r\n";
    r << L"- Arêtes CFG : " << edges << L"\r\n";
    r << L"- Branches : " << branches << L"\r\n";
    r << L"- Retours : " << returns << L"\r\n";
    r << L"- Appels directs détectés : " << calls << L"\r\n";
    r << L"- Appels importés annotés : " << importCalls << L"\r\n";
    r << L"- IAT résolue : " << iatMap.size() << L" entrées\r\n";
    r << L"- Thunks d'import détectés : " << thunks.size() << L"\r\n";
    r << L"- Jump tables candidates : " << jumpTables.size() << L"\r\n";
    r << L"- Candidats fonctions par prologue : " << funcs.size() << L"\r\n\r\n";

    r << L"## IAT / imports annotés\r\n";
    size_t shownIat = 0;
    for (const auto& kv : iatMap) {
        r << L"- " << Hex64(kv.first, 8) << L" -> " << kv.second << L"\r\n";
        if (++shownIat >= 200) { r << L"- ... IAT tronquée\r\n"; break; }
    }
    if (iatMap.empty()) r << L"- Aucune entrée IAT exploitable.\r\n";

    r << L"\r\n## Thunks d'import\r\n";
    for (const auto& t : thunks) r << L"- " << Hex64(t.va, 8) << L" -> " << t.importName << L" (`" << t.pattern << L"`)\r\n";
    if (thunks.empty()) r << L"- Aucun thunk direct IAT détecté dans cette section.\r\n";

    r << L"\r\n## Jump tables candidates\r\n";
    for (const auto& jt : jumpTables) r << L"- instruction " << Hex64(jt.instrVa, 8) << L", table=" << (jt.tableVa ? Hex64(jt.tableVa, 8) : L"inconnue") << L", opérande=`" << jt.operand << L"`\r\n";
    if (jumpTables.empty()) r << L"- Aucune jump table candidate détectée dans cette section.\r\n";

    r << L"\r\n## Candidats fonctions\r\n";
    size_t shown = 0;
    for (uint64_t off : funcs) {
        r << L"- " << Hex64(sectionBase + off, 8) << L"\r\n";
        if (++shown >= 1000) { r << L"- ... liste tronquée\r\n"; break; }
    }
    r << GenerateDeepDecompilerReport(disasm, blocks, funcs, iatMap);

    r << L"\r\n## Notes techniques honnêtes\r\n";
    r << L"- V16 reconstruit CFG, prémices SSA, types, classes/RTTI candidates, exceptions et appels indirects par heuristiques statiques.\r\n";
    r << L"- Les appels indirects IAT sont résolus ; les appels calculés non prouvés restent annotés comme indirects.\r\n";
    r << L"- Les jump tables sont détectées par heuristique ; la reconstruction exacte de tous les switch demande une propagation interprocédurale complète.\r\n";
    r << L"- Les sections packed/chiffrées sont signalées plutôt que transformées en faux C.\r\n";
    return r.str();
}

static bool ExportAdvancedArtifacts(const std::wstring& sectionName,
                                    const std::map<uint64_t, std::wstring>& disasm,
                                    const std::vector<BasicBlock>& blocks,
                                    const std::vector<uint64_t>& funcs,
                                    uint64_t sectionBase,
                                    const std::map<uint64_t, std::wstring>& iatMap = std::map<uint64_t, std::wstring>(),
                                    const std::vector<ThunkInfo>& thunks = std::vector<ThunkInfo>(),
                                    const std::vector<JumpTableInfo>& jumpTables = std::vector<JumpTableInfo>()) {
    if (disasm.empty() || blocks.empty()) return false;
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) { AppendLog(L"[ERREUR] " + err); return false; }
    std::wstring base = SanitizeFileNamePart(sectionName);
    bool ok = true;
    ok = WriteUtf8TextFile(dir + L"\\" + base + L"_cfg.dot", GenerateCfgDot(sectionName, blocks), false) && ok;
    ok = WriteUtf8TextFile(dir + L"\\" + base + L"_callgraph.dot", GenerateCallGraphDot(sectionName, blocks, thunks), false) && ok;
    ok = WriteUtf8TextFile(dir + L"\\" + base + L"_advanced.md", GenerateAdvancedFunctionReport(sectionName, disasm, blocks, funcs, sectionBase, iatMap, thunks, jumpTables), true) && ok;
    if (ok) AppendLog(L"[OK] Artefacts avancés CFG/callgraph/IAT exportés pour " + sectionName);
    return ok;
}

// --------------------------- Fenêtre de progression ---------------------------
static LRESULT CALLBACK ProgressWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hProgressBar = CreateWindowW(PROGRESS_CLASS, nullptr,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            10, 30, 280, 20, hwnd, (HMENU)IDC_PROGRESS, g_hInst, nullptr);
        SendMessageW(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 1000));
        SendMessageW(g_hProgressBar, PBM_SETPOS, 0, 0);

        g_hProgressText = CreateWindowW(L"STATIC", L"Analyse en cours...",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            10, 10, 280, 20, hwnd, (HMENU)IDC_PROGRESS_TEXT, g_hInst, nullptr);
        return 0;
    }
    case WM_DESTROY:
        g_hProgressBar = nullptr;
        g_hProgressText = nullptr;
        g_hProgressWnd = nullptr;
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

static void ShowProgressWindow(const std::wstring& title) {
    if (g_hProgressWnd) return;
    g_hProgressWnd = CreateWindowW(L"STATIC", title.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 360, 120,
        g_hWnd, nullptr, g_hInst, nullptr);
    SendMessageW(g_hProgressWnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP)));
    SendMessageW(g_hProgressWnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
    SetWindowLongPtrW(g_hProgressWnd, GWLP_WNDPROC, (LONG_PTR)ProgressWndProc);
    SendMessageW(g_hProgressWnd, WM_CREATE, 0, 0);
}

static void UpdateProgress(int percent, const std::wstring& text) {
    if (g_hProgressBar) {
        SendMessageW(g_hProgressBar, PBM_SETPOS, (WPARAM)(percent * 10), 0);
    }
    if (g_hProgressText) {
        SetWindowTextW(g_hProgressText, text.c_str());
    }
    if (g_hProgressWnd) {
        MSG msg;
        while (PeekMessageW(&msg, g_hProgressWnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

static void CloseProgressWindow() {
    if (g_hProgressWnd) {
        DestroyWindow(g_hProgressWnd);
        g_hProgressWnd = nullptr;
        g_hProgressBar = nullptr;
        g_hProgressText = nullptr;
    }
}


// --------------------------- Résolution IAT / thunks / jump tables ---------------------------
static std::wstring ImportDisplayName(const ImportEntry& im) {
    std::wstring name = im.name.empty() ? L"<import?>" : im.name;
    if (im.byOrdinal && im.ordinal) name = L"#" + Dec(im.ordinal);
    return im.dll + L"!" + name;
}

static std::map<uint64_t, std::wstring> BuildIatNameMap(const PeInfo& pi) {
    std::map<uint64_t, std::wstring> out;
    for (const auto& im : pi.imports) {
        if (im.iatVa) out[im.iatVa] = ImportDisplayName(im);
        if (im.iatRva) out[pi.imageBase + im.iatRva] = ImportDisplayName(im);
    }
    return out;
}

static std::vector<uint64_t> ExtractHexValues(const std::wstring& text) {
    std::vector<uint64_t> vals;
    size_t pos = 0;
    while ((pos = text.find(L"0x", pos)) != std::wstring::npos) {
        const wchar_t* p = text.c_str() + pos;
        wchar_t* endp = nullptr;
        uint64_t v = _wcstoui64(p, &endp, 16);
        if (endp && endp > p) { vals.push_back(v); pos = (size_t)(endp - text.c_str()); }
        else pos += 2;
    }
    return vals;
}

static std::wstring ResolveImportInOperand(const std::wstring& operand, const std::map<uint64_t, std::wstring>& iatMap) {
    for (uint64_t v : ExtractHexValues(operand)) {
        auto it = iatMap.find(v);
        if (it != iatMap.end()) return it->second;
    }
    return L"";
}

static std::map<uint64_t, std::wstring> AnnotateDisassemblyWithImports(std::map<uint64_t, std::wstring> disasm,
                                                                       const std::map<uint64_t, std::wstring>& iatMap) {
    if (iatMap.empty()) return disasm;
    for (auto& kv : disasm) {
        std::wstring asmText = StripAddressFromDisasmLine(kv.second);
        std::wstring ops = OperandsFromAsmText(asmText);
        std::wstring imp = ResolveImportInOperand(ops, iatMap);
        if (!imp.empty() && kv.second.find(L"; import ") == std::wstring::npos) {
            kv.second += L"    ; import " + imp;
        }
    }
    return disasm;
}

static std::vector<ThunkInfo> DetectImportThunks(const std::map<uint64_t, std::wstring>& disasm,
                                                 const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<ThunkInfo> out;
    std::set<uint64_t> seen;
    for (const auto& kv : disasm) {
        std::wstring asmText = StripAddressFromDisasmLine(kv.second);
        std::wstring mn = MnemonicFromAsmText(asmText);
        if (!(mn == L"jmp" || mn == L"call" || mn == L"mov")) continue;
        std::wstring ops = OperandsFromAsmText(asmText);
        std::wstring imp = ResolveImportInOperand(ops, iatMap);
        if (!imp.empty() && seen.insert(kv.first).second) {
            ThunkInfo t;
            t.va = kv.first;
            t.importName = imp;
            t.pattern = asmText;
            out.push_back(t);
        }
    }
    return out;
}

static bool LooksLikeIndirectMemoryTransfer(const std::wstring& mn, const std::wstring& ops) {
    if (!(mn == L"jmp" || mn == L"call")) return false;
    std::wstring o = LowerW(ops);
    return o.find(L"[") != std::wstring::npos && o.find(L"]") != std::wstring::npos;
}

static std::vector<JumpTableInfo> DetectJumpTables(const std::map<uint64_t, std::wstring>& disasm,
                                                   const std::map<uint64_t, std::wstring>& iatMap) {
    std::vector<JumpTableInfo> out;
    for (const auto& kv : disasm) {
        std::wstring asmText = StripAddressFromDisasmLine(kv.second);
        std::wstring mn = MnemonicFromAsmText(asmText);
        std::wstring ops = StripAsmTrailingComment(OperandsFromAsmText(asmText));
        if (!LooksLikeIndirectMemoryTransfer(mn, ops)) continue;
        if (!ResolveImportInOperand(ops, iatMap).empty()) continue; // IAT, pas jump table.
        std::wstring lo = LowerW(ops);
        if (mn == L"jmp" && (lo.find(L"*") != std::wstring::npos || lo.find(L"+") != std::wstring::npos || lo.find(L"rip") != std::wstring::npos || lo.find(L"eax") != std::wstring::npos || lo.find(L"ecx") != std::wstring::npos || lo.find(L"edx") != std::wstring::npos)) {
            JumpTableInfo jt;
            jt.instrVa = kv.first;
            jt.tableVa = ParseLastHexImmediate(ops);
            jt.operand = ops;
            out.push_back(jt);
        }
    }
    return out;
}

static std::wstring SectionNameForVa(const PeInfo& pi, uint64_t va) {
    for (const auto& sec : pi.sections) {
        uint64_t a = pi.imageBase + sec.va;
        uint64_t b = a + std::max<uint32_t>(sec.vs, sec.rawSize);
        if (va >= a && va < b) return sec.name;
    }
    return L"<externe>";
}

static bool ExportInterSectionCallGraph(const PeInfo& pi, const std::vector<AdvancedSectionResult>& results,
                                        const std::map<uint64_t, std::wstring>& iatMap) {
    if (results.empty()) return false;
    std::wstring dir, err;
    if (!GetOutputDirChecked(dir, err)) { AppendLog(L"[ERREUR] " + err); return false; }
    std::wstringstream dot;
    dot << L"digraph ZennComp_InterSection_CallGraph {\n";
    dot << L"  graph [label=\"ZennComp call graph inter-sections + IAT\", labelloc=t, fontsize=18];\n";
    dot << L"  node [fontname=\"Consolas\"];\n";
    std::set<std::wstring> emitted;
    auto node = [](uint64_t va) { return std::wstring(L"sub_") + Hex64(va, 8); };
    for (const auto& r : results) {
        for (const auto& b : r.blocks) {
            std::wstring src = node(b.start);
            if (emitted.insert(src).second) dot << L"  \"" << src << L"\" [shape=box,label=\"" << Hex64(b.start, 8) << L"\\n" << DotEscape(r.name) << L"\"];\n";
            for (uint64_t c : b.calls) {
                std::wstring dst = node(c);
                std::wstring dstSec = SectionNameForVa(pi, c);
                if (emitted.insert(dst).second) dot << L"  \"" << dst << L"\" [shape=box,label=\"" << Hex64(c, 8) << L"\\n" << DotEscape(dstSec) << L"\"];\n";
                dot << L"  \"" << src << L"\" -> \"" << dst << L"\";\n";
            }
        }
        for (const auto& th : r.thunks) {
            std::wstring src = node(th.va);
            std::wstring dst = std::wstring(L"imp_") + SanitizeIdentifier(th.importName);
            dot << L"  \"" << src << L"\" [shape=box,label=\"" << Hex64(th.va, 8) << L"\\nthunk\"];\n";
            dot << L"  \"" << dst << L"\" [shape=ellipse,label=\"" << DotEscape(th.importName) << L"\"];\n";
            dot << L"  \"" << src << L"\" -> \"" << dst << L"\" [label=\"IAT\"];\n";
        }
    }
    if (iatMap.empty()) dot << L"  imports [shape=note,label=\"Aucune IAT exploitable détectée\"];\n";
    dot << L"}\n";
    bool ok = WriteUtf8TextFile(dir + L"\\zenncomp_intersection_callgraph.dot", dot.str(), false);
    if (ok) AppendLog(L"[OK] Call graph inter-sections exporté : zenncomp_intersection_callgraph.dot");
    return ok;
}

// --------------------------- Pseudo-code amélioré ---------------------------
static std::wstring BuildPseudoCode(const PeInfo& pi) {
    std::wstringstream ss;
    ss << GeneratedCRuntimeHeader(false);
    ss << L"\r\n";
    ss << L"/* ===============================================================\r\n";
    ss << L"   PSEUDO-DECOMPILATION ZENNCOMP\r\n";
    ss << L"   Reconstruction statique clean-room basée sur PE headers, imports, chaînes et désassemblage.\r\n";
    ss << L"   Ce fichier est recompilable comme stub d'audit ; il ne reconstitue pas bit-à-bit le binaire original.\r\n";
    ss << L"   =============================================================== */\r\n\r\n";
    ss << L"int zenncomp_summary_main(void) {\r\n";
    ss << L"    ZC_OP(\"image_base\", \"" << Hex64(pi.imageBase, pi.is64 ? 16 : 8) << L"\");\r\n";
    ss << L"    ZC_OP(\"entry_point_rva\", \"" << Hex64(pi.entryRva, 8) << L"\");\r\n\r\n";

    if (HasImport(pi, L"GetVersion") || HasImport(pi, L"RtlGetVersion"))
        ss << L"    ZC_OP(\"behavior\", \"query_windows_version\");\r\n";
    if (HasImport(pi, L"CreateFile") || HasImport(pi, L"ReadFile") || HasImport(pi, L"WriteFile"))
        ss << L"    ZC_OP(\"behavior\", \"inspect_or_modify_filesystem_objects\");\r\n";
    if (HasImport(pi, L"RegOpenKey") || HasImport(pi, L"RegSetValue") || HasImport(pi, L"RegDelete"))
        ss << L"    ZC_OP(\"behavior\", \"inspect_or_modify_registry_keys\");\r\n";
    if (HasImport(pi, L"OpenSCManager") || HasImport(pi, L"CreateService") || HasImport(pi, L"DeleteService"))
        ss << L"    ZC_OP(\"behavior\", \"inspect_or_modify_windows_services\");\r\n";
    if (HasImport(pi, L"CreateProcess") || HasImport(pi, L"ShellExecute") || HasImport(pi, L"WinExec"))
        ss << L"    ZC_OP(\"behavior\", \"launch_external_command_or_helper\");\r\n";
    if (HasImport(pi, L"Internet") || HasImport(pi, L"WinHttp") || HasImport(pi, L"URLDownload"))
        ss << L"    ZC_OP(\"behavior\", \"contact_or_download_remote_resource\");\r\n";
    if (HasImport(pi, L"VirtualAlloc") || HasImport(pi, L"VirtualProtect"))
        ss << L"    ZC_OP(\"behavior\", \"allocate_or_change_executable_memory\");\r\n";
    if (HasImport(pi, L"LoadLibrary") || HasImport(pi, L"GetProcAddress"))
        ss << L"    ZC_OP(\"behavior\", \"resolve_dynamic_api_calls\");\r\n";

    ss << L"\r\n    /* Modules probables détectés par table d'import: */\r\n";
    std::map<std::wstring, int> dlls;
    for (const auto& im : pi.imports) dlls[im.dll]++;
    for (const auto& kv : dlls) {
        ss << L"    /* " << kv.first << L" : " << kv.second << L" fonctions importées */\r\n";
    }
    ss << L"    return 0;\r\n";
    ss << L"}\r\n\r\n";

    // Ajoute aussi une pseudo-décompilation du point d'entrée et des sections exécutables.
    for (const auto& sec : pi.sections) {
        if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        SectionBytes bytes;
        std::wstring reason;
        if (!ResolveSectionBytes(sec, bytes, reason)) continue;
        uint64_t base = pi.imageBase + sec.va;
        try {
            auto funcs = FindFunctionStarts(bytes.data, bytes.size, pi.is64);
            auto pdataRanges = RuntimeFunctionsForSection(pi, sec, bytes.size);
            auto pdataFuncs = RuntimeFunctionStartsForSection(pi, sec, bytes.size);
            MergeUniqueStarts(funcs, pdataFuncs);
            std::map<uint64_t, std::wstring> disasm;
            if (pi.is64 && !pdataRanges.empty()) {
                disasm = BuildDisassemblyByRuntimeFunctions(bytes.data, bytes.size, base, sec.va, pi.is64, pdataRanges);
            } else {
                disasm = DisassembleRecursive(bytes.data, bytes.size, base, pi.is64, &funcs);
                if (disasm.empty()) disasm = BuildDisassembly(bytes.data, bytes.size, base, pi.is64);
            }
            if (!disasm.empty()) {
                auto blocks = BuildBasicBlocks(disasm);
                ss << GeneratePseudoC(blocks, L"zc_" + SanitizeIdentifier(sec.name) + L"_standard", false);
                ss << L"\r\n";
            }
        } catch (...) {
            ss << L"/* Section " << sec.name << L" : pseudo-décompilation impossible. */\r\n";
        }
    }

    return ss.str();
}

// --------------------------- Analyse standard avec progression ---------------------------
static std::wstring AnalyzeCurrentFile(bool includeStrings, bool includePseudo, bool includeDisasm) {
    UpdateProgress(20, L"Analyse des headers PE...");
    std::wstringstream report;
    if (g_file.empty() || g_targetPath.empty()) {
        return L"[ERREUR] Aucun fichier charge. Clique sur Ouvrir EXE.\r\n";
    }

    std::wstring packerName;
    if (DetectPackerBySignatures(g_file.data(), g_file.size(), packerName)) {
        report << L"[PACKER] Signature détectée : " << packerName << L"\r\n";
    }

    std::wstring err;
    PeInfo pi;
    PeParser parser(g_file);
    if (!parser.Parse(pi, err)) {
        report << L"[ERREUR] Analyse PE impossible: " << err << L"\r\n";
        return report.str();
    }

    UpdateProgress(40, L"Génération du rapport...");
    auto iatMap = BuildIatNameMap(pi);
    std::vector<AdvancedSectionResult> advancedSections;

    report << L"================ ZennComp V16 Unwind-Aware Engine - Rapport statique avancé ================\r\n";
    report << L"Fichier     : " << g_targetPath << L"\r\n";
    report << L"Nom         : " << BaseName(g_targetPath) << L"\r\n";
    report << L"Taille      : " << Dec(g_file.size()) << L" octets\r\n";
    report << L"FNV1a-64    : " << Hex64(Fnv1a64(g_file), 16) << L"\r\n";
    report << L"Format      : PE " << (pi.is64 ? L"64 bits" : L"32 bits") << L"\r\n";
    report << L"Machine     : " << MachineName(pi.machine) << L"\r\n";
    report << L"Subsystem   : " << SubsystemName(pi.subsystem) << L"\r\n";
    report << L"ImageBase   : " << Hex64(pi.imageBase, pi.is64 ? 16 : 8) << L"\r\n";
    report << L"Entry RVA   : " << Hex64(pi.entryRva, 8) << L"\r\n";
    report << L"Sections    : " << Dec(pi.sections.size()) << L"\r\n";
    report << L"Imports     : " << Dec(pi.imports.size()) << L" fonctions\r\n";
    report << L"IAT résolue : " << Dec(iatMap.size()) << L" entrées\r\n";
    report << L"Dir import  : RVA=" << Hex64(pi.importRva, 8) << L" size=" << Dec(pi.importSize) << L"\r\n";
    report << L"Dir export  : RVA=" << Hex64(pi.exportRva, 8) << L" size=" << Dec(pi.exportSize) << L"\r\n";
    report << L"Dir resource: RVA=" << Hex64(pi.resourceRva, 8) << L" size=" << Dec(pi.resourceSize) << L"\r\n";
    report << L"Dir exception/.pdata: RVA=" << Hex64(pi.exceptionRva, 8) << L" size=" << Dec(pi.exceptionSize)
           << L" runtime_functions=" << Dec(pi.runtimeFunctions.size()) << L"\r\n\r\n";

    report << L"[SECTIONS]\r\n";
    for (const auto& s : pi.sections) {
        double ent = 0.0;
        if (s.raw < g_file.size()) {
            size_t avail = std::min<size_t>(s.rawSize, g_file.size() - s.raw);
            ent = Entropy(g_file.data() + s.raw, avail);
        }
        report << L" - " << s.name
               << L" VA=" << Hex64(s.va, 8)
               << L" VS=" << Hex64(s.vs, 8)
               << L" RAW=" << Hex64(s.raw, 8)
               << L" RS=" << Hex64(s.rawSize, 8)
               << L" ENT=" << std::fixed << std::setprecision(2) << ent
               << L" CH=" << Hex64(s.characteristics, 8)
               << L"\r\n";
    }

    bool upxFound = false;
    for (const auto& s : pi.sections) {
        if (s.name == L"UPX0" || s.name == L"UPX1") upxFound = true;
    }
    if (upxFound) {
        report << L"\n[AVERTISSEMENT] Le fichier semble compresse avec UPX.\n";
        report << L"Le desassemblage direct sur les sections UPX ne donnera pas de code exploitable.\n";
        report << L"Utilisez le bouton 'Décompresser UPX' d'abord.\n\n";
    }

    report << L"\r\n[IMPORTS PAR DLL]\r\n";
    std::map<std::wstring, std::vector<std::wstring>> byDll;
    for (const auto& im : pi.imports) byDll[im.dll].push_back(im.name);
    for (auto& kv : byDll) {
        report << L"\r\n" << kv.first << L"\r\n";
        size_t limit = std::min<size_t>(kv.second.size(), 120);
        for (size_t i = 0; i < limit; ++i) report << L"    " << kv.second[i] << L"\r\n";
        if (kv.second.size() > limit) report << L"    ... (" << Dec(kv.second.size() - limit) << L" autres)\r\n";
    }

    report << L"\r\n[HEURISTIQUES]\r\n";
    auto mark = [&](const wchar_t* label, bool yes, const wchar_t* why) {
        report << L" - " << (yes ? L"[OUI] " : L"[NON] ") << label << L" : " << why << L"\r\n";
    };
    mark(L"Manipulation fichiers", HasImport(pi, L"CreateFile") || HasImport(pi, L"DeleteFile") || HasImport(pi, L"MoveFile"), L"CreateFile/DeleteFile/MoveFile");
    mark(L"Manipulation registre", HasImport(pi, L"RegOpenKey") || HasImport(pi, L"RegSetValue") || HasImport(pi, L"RegDelete"), L"API Reg*");
    mark(L"Execution processus", HasImport(pi, L"CreateProcess") || HasImport(pi, L"ShellExecute") || HasImport(pi, L"WinExec"), L"CreateProcess/ShellExecute/WinExec");
    mark(L"Services Windows", HasImport(pi, L"OpenSCManager") || HasImport(pi, L"CreateService") || HasImport(pi, L"DeleteService"), L"Service Control Manager");
    mark(L"Resolution API dynamique", HasImport(pi, L"LoadLibrary") || HasImport(pi, L"GetProcAddress"), L"LoadLibrary/GetProcAddress");
    mark(L"Memoire executable", HasImport(pi, L"VirtualAlloc") || HasImport(pi, L"VirtualProtect"), L"VirtualAlloc/VirtualProtect");
    mark(L"Reseau / HTTP", HasImport(pi, L"Internet") || HasImport(pi, L"WinHttp") || HasImport(pi, L"URLDownload"), L"WinINet/WinHTTP/URLDownload");

    if (includeDisasm) {
        std::wstring outDir, outErr;
        if (GetOutputDirChecked(outDir, outErr)) {
            AppendLog(L"[INFO] Dossier de sortie : " + outDir);
        } else {
            AppendLog(L"[ERREUR] " + outErr);
        }

        UpdateProgress(60, L"Désassemblage linéaire...");
        report << L"\r\n[DISASSEMBLY (LINEAR)]\r\n";
        int totalExecSections = 0;
        for (const auto& sec : pi.sections) {
            if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) totalExecSections++;
        }
        if (totalExecSections == 0) {
            AppendLog(L"[WARN] Aucune section exécutable. Le mode standard n'exportera pas d'ASM section par section ; utilisez Bruteforce pour toutes les sections.");
        }

        int processed = 0;
        for (const auto& sec : pi.sections) {
            if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            processed++;
            int progress = totalExecSections > 0 ? 60 + (processed * 30 / totalExecSections) : 90;
            UpdateProgress(progress, L"Désassemblage de " + sec.name);

            SectionBytes bytes;
            std::wstring reason;
            if (!ResolveSectionBytes(sec, bytes, reason)) {
                AppendLog(L"[WARN] Section " + sec.name + L" ignorée : " + reason);
                report << L"\n--- " << sec.name << L" ignorée : " << reason << L" ---\n";
                continue;
            }
            if (bytes.virtualOnly) {
                AppendLog(L"[WARN] Section " + sec.name + L" sans RAW : buffer virtuel zero-fill de " + Dec(bytes.size) + L" octets.");
            }
            if (bytes.truncated) {
                AppendLog(L"[WARN] Section " + sec.name + L" tronquée par contrainte mémoire exceptionnelle à " + Dec(bytes.size) + L" octets.");
            }

            std::map<uint64_t, std::wstring> disasmRec;
            std::map<uint64_t, std::wstring> disasmLin;
            std::vector<uint64_t> funcs;
            uint64_t base = pi.imageBase + sec.va;
            try {
                funcs = FindFunctionStarts(bytes.data, bytes.size, pi.is64);
                auto pdataRanges = RuntimeFunctionsForSection(pi, sec, bytes.size);
                auto pdataFuncs = RuntimeFunctionStartsForSection(pi, sec, bytes.size);
                if (!pdataFuncs.empty()) {
                    AppendLog(L"[INFO] " + Dec(pdataFuncs.size()) + L" fonctions récupérées via .pdata/unwind pour " + sec.name);
                    report << L"Fonctions récupérées via .pdata/unwind : " << pdataFuncs.size() << L"\n";
                    ExportRuntimeFunctionIndex(sec.name, pdataRanges);
                }
                MergeUniqueStarts(funcs, pdataFuncs);
                if (pi.is64 && !pdataRanges.empty()) {
                    AppendLog(L"[INFO] Mode standard x64 unwind-aware : désassemblage par plages .pdata pour " + sec.name);
                    disasmRec = BuildDisassemblyByRuntimeFunctions(bytes.data, bytes.size, base, sec.va, pi.is64, pdataRanges);
                    disasmLin = disasmRec;
                } else {
                    disasmRec = DisassembleRecursive(bytes.data, bytes.size, base, pi.is64, &funcs);
                    disasmLin = BuildDisassembly(bytes.data, bytes.size, base, pi.is64);
                }
                disasmRec = AnnotateDisassemblyWithImports(disasmRec, iatMap);
                disasmLin = AnnotateDisassemblyWithImports(disasmLin, iatMap);
                const auto& qualityDisasm = !disasmRec.empty() ? disasmRec : disasmLin;
                CodeQualityMetrics quality = AssessCodeQuality(bytes.data, bytes.size, qualityDisasm, funcs, true);
                if (quality.probablyPackedOrEncrypted) {
                    AppendLog(L"[WARN] " + sec.name + L" semble packée/chiffrée : export triage au lieu de faux pseudo-C.");
                    ExportPackedTriageReport(sec, bytes, quality, funcs, qualityDisasm);
                }
            } catch (const std::exception& e) {
                AppendLog(L"[ERREUR] Désassemblage standard échoué pour " + sec.name + L" : " + Utf8ToWide(e.what()));
                report << L"\n--- " << sec.name << L" : erreur désassemblage : " << Utf8ToWide(e.what()) << L" ---\n";
                continue;
            } catch (...) {
                AppendLog(L"[ERREUR] Désassemblage standard échoué pour " + sec.name + L" : exception non standard.");
                report << L"\n--- " << sec.name << L" : erreur désassemblage non standard ---\n";
                continue;
            }

            const auto& bestDisasm = !disasmRec.empty() ? disasmRec : disasmLin;
            CodeQualityMetrics stdQuality = AssessCodeQuality(bytes.data, bytes.size, bestDisasm, funcs, true);
            report << L"\nQualité code " << sec.name << L" : entropie=" << std::fixed << std::setprecision(3) << stdQuality.entropy
                   << L", DB=" << std::fixed << std::setprecision(2) << (stdQuality.dbRatio * 100.0) << L"%, verdict=" << stdQuality.verdict << L"\n";
            if (stdQuality.probablyPackedOrEncrypted) {
                report << L"[WARN] Pseudo-C standard désactivé : section probablement packée/chiffrée. Voir triage exporté.\n";
                ExportPackedTriageReport(sec, bytes, stdQuality, funcs, bestDisasm);
                continue;
            }
            report << L"\n--- " << sec.name << L" (récursif=" << disasmRec.size() << L", linéaire=" << disasmLin.size() << L") ---\n";
            size_t shown = 0;
            for (const auto& [addr, line] : bestDisasm) {
                if (shown++ >= ZC_MAX_REPORT_INSTRUCTIONS_PER_SECTION) {
                    report << L"... rapport tronqué, exports complets sur disque ...\n";
                    break;
                }
                report << line << L"\n";
            }

            if (!disasmLin.empty()) ExportDisassemblyToFile(disasmLin, sec.name, L"_linear");
            if (!disasmRec.empty()) ExportDisassemblyToFile(disasmRec, sec.name, L"_recursive");

            if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE) && bytes.size > 0) {
                ExportStringsFromSection(sec, bytes, outDir);
            }

            if (!bestDisasm.empty()) {
                auto blocks = BuildBasicBlocks(bestDisasm);
                auto thunks = DetectImportThunks(bestDisasm, iatMap);
                auto jumpTables = DetectJumpTables(bestDisasm, iatMap);
                ExportAdvancedArtifacts(sec.name, bestDisasm, blocks, funcs, base, iatMap, thunks, jumpTables);
                AdvancedSectionResult ar; ar.name = sec.name; ar.start = base; ar.end = base + bytes.size; ar.blocks = blocks; ar.thunks = thunks; ar.jumpTables = jumpTables; advancedSections.push_back(ar);
                std::wstring pseudo = GeneratePseudoC(blocks, L"zc_" + SanitizeIdentifier(sec.name) + L"_standard", true, true);
                ExportPseudoCToFile(pseudo, sec.name, L"_decompiled");
            } else {
                std::wstringstream stub;
                stub << L"#include \"zenncomp_runtime.h\"\n\n";
                stub << L"void zc_" << SanitizeIdentifier(sec.name) << L"_standard_stub(void) {\n";
                stub << L"    ZC_OP(\"section\", \"" << EscapeCStringW(sec.name) << L"\");\n";
                stub << L"    ZC_OP(\"reason\", \"aucune instruction decodable par Capstone ni fallback interne\");\n";
                stub << L"}\n";
                ExportPseudoCToFile(stub.str(), sec.name, L"_decompiled");
                AppendLog(L"[WARN] Pseudo-C stub généré pour " + sec.name + L" : aucune instruction décodable.");
            }
        }
    }

    if (!advancedSections.empty()) {
        ExportInterSectionCallGraph(pi, advancedSections, iatMap);
    }

    if (includePseudo) {
        UpdateProgress(90, L"Génération du pseudo-code...");
        std::wstring pseudo = BuildPseudoCode(pi);
        report << pseudo;

        std::wstring base = BaseName(g_targetPath);
        size_t ext = base.find_last_of(L'.');
        if (ext != std::wstring::npos) base = base.substr(0, ext);
        ExportPseudoCToFile(pseudo, base, L"_decompiled");
    }

    if (includeStrings) {
        UpdateProgress(95, L"Extraction des chaînes...");
        report << L"\r\n[CHAINES ASCII]\r\n";
        auto ascii = ExtractAsciiStrings(5, 500);
        for (const auto& s : ascii) report << s << L"\r\n";
        report << L"\r\n[CHAINES UTF-16]\r\n";
        auto wide = ExtractUtf16Strings(5, 200);
        for (const auto& s : wide) report << s << L"\r\n";
    }

    report << L"\r\n[FIN]\r\n";
    UpdateProgress(100, L"Terminé");
    return report.str();
}

// --------------------------- Analyse standard (threadée) ---------------------------
struct StandardAnalysisParams {
    PeInfo pi;
    bool includeStrings;
    bool includePseudo;
    bool includeDisasm;
    std::wstring result;
    bool finished = false;
    bool cancelled = false;
};

static unsigned int __stdcall StandardAnalysisThreadFunc(void* param) {
    _set_se_translator(SeTranslator);
    StandardAnalysisParams* p = (StandardAnalysisParams*)param;
    try {
        std::wstring result = AnalyzeCurrentFile(p->includeStrings, p->includePseudo, p->includeDisasm);
        p->result = result;
        p->finished = true;
    } catch (const std::exception& e) {
        p->result = L"[ERREUR] Exception C++ : " + Utf8ToWide(e.what()) + L"\r\n";
        p->finished = true;
    } catch (...) {
        p->result = L"[ERREUR] Exception inconnue.\r\n";
        p->finished = true;
    }
    return 0;
}

static unsigned int __stdcall DumpLiveThreadFunc(void* param) {
    (void)param;
    _set_se_translator(SeTranslator);

    // Fonction pour remettre le texte du bouton à "DumpLive" en fin de thread
    auto resetButtonText = []() {
        HWND hBtn = GetDlgItem(g_hWnd, IDC_BTN_DUMPLIVE);
        if (hBtn) SetWindowTextW(hBtn, L"DumpLive");
    };

    // Créer un fichier de sortie avec horodatage
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t fileName[MAX_PATH];
    wsprintfW(fileName, L"dumplive_%04d%02d%02d_%02d%02d%02d.c",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::wstring outPath = g_lastOutputDir + L"\\" + fileName;
    if (g_lastOutputDir.empty()) {
        std::wstring err;
        if (!GetOutputDirChecked(g_lastOutputDir, err)) {
            AppendLog(L"[ERREUR] Impossible de créer le dossier de sortie : " + err);
            g_dumpLiveRunning = false;
            resetButtonText();
            return 1;
        }
        outPath = g_lastOutputDir + L"\\" + fileName;
    }

    // En-tête du fichier
    std::wstringstream header;
    header << L"/* DumpLive - ZennComp - " << g_targetPath << L" */\n";
    header << L"/* Base: " << Hex64(g_imageBase, 16) << L" - Taille: " << Dec(g_imageSize) << L" */\n\n";
    WriteUtf8TextFile(outPath, header.str());

    AppendLog(L"[INFO] DumpLive démarré, sortie : " + outPath);

    uint64_t currentAddr = g_imageBase;
    uint64_t endAddr = g_imageBase + g_imageSize;
    const size_t BLOCK_SIZE = 1024 * 1024;  // 1 Mo par lecture
    std::vector<uint8_t> buffer(BLOCK_SIZE);

    while (g_dumpLiveRunning && currentAddr < endAddr) {
        SIZE_T toRead = (SIZE_T)std::min<uint64_t>(BLOCK_SIZE, endAddr - currentAddr);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(g_hProcess, (LPCVOID)currentAddr, buffer.data(), toRead, &bytesRead) || bytesRead == 0) {
            // Région non lisible : on saute une page
            currentAddr += 0x1000;
            continue;
        }

        // Désassembler le bloc lu (avec protection contre les exceptions)
        try {
            bool is64 = true; // À adapter selon le binaire cible (vous pouvez stocker un booléen global)
            auto disasm = BuildDisassembly(buffer.data(), bytesRead, currentAddr, is64);
            if (!disasm.empty()) {
                auto blocks = BuildBasicBlocks(disasm);
                if (!blocks.empty()) {
                    std::wstring pseudo = GeneratePseudoC(blocks,
                                                          L"zc_dumplive_" + Hex64(currentAddr, 16),
                                                          false,  // pas de header runtime (déjà inclus)
                                                          true); // commentaires ASM
                    AppendLog(L"[DumpLive] Adresse 0x" + Hex64(currentAddr, 16) + L" : " + Dec(blocks.size()) + L" blocs");
                    AppendLog(pseudo);

                    // Ajouter au fichier
                    std::wstringstream blockContent;
                    blockContent << L"\n/* --- Bloc 0x" << Hex64(currentAddr, 16) << L" --- */\n";
                    blockContent << pseudo << L"\n";
                    WriteUtf8TextFile(outPath, blockContent.str(), false); // mode append
                }
            }
        } catch (const std::exception& e) {
            AppendLog(L"[ERREUR] Exception lors du désassemblage à 0x" + Hex64(currentAddr, 16) + L" : " + Utf8ToWide(e.what()));
        } catch (...) {
            AppendLog(L"[ERREUR] Exception inconnue lors du désassemblage à 0x" + Hex64(currentAddr, 16));
        }

        currentAddr += bytesRead;
        Sleep(50); // ne pas saturer le CPU
    }

    AppendLog(L"[INFO] DumpLive terminé (dernière adresse : " + Hex64(currentAddr, 16) + L")");
    g_dumpLiveRunning = false;
    resetButtonText();
    SetStatus(L"DumpLive terminé");
    return 0;
}

// --------------------------- Analyse brute-force (threadée) avec exports ---------------------------
struct BruteforceThreadParams {
    PeInfo pi;
    std::wstring result;
    bool finished = false;
    bool cancelled = false;
    bool enableXdr = false;
};

// Helper : calcule l'entropie d'un buffer
static double XdrEntropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double e = 0.0;
    for (uint64_t c : freq) {
        if (!c) continue;
        double p = (double)c / (double)len;
        e -= p * (std::log(p) / std::log(2.0));
    }
    return e;
}

// Recherche une clé XOR 1 octet qui minimise l'entropie avec progression
static bool FindXorKey1Byte(const uint8_t* data, size_t size, uint8_t& bestKey, double& bestEntropy) {
    if (size == 0) return false;
    // Échantillon de 512 Ko
    const size_t sampleSize = std::min<size_t>(size, 512 * 1024);
    std::vector<uint8_t> sample(data, data + sampleSize);
    double origEntropy = XdrEntropy(sample.data(), sampleSize);
    bestKey = 0;
    bestEntropy = origEntropy;
    bool improved = false;
    std::vector<uint8_t> decrypted(sampleSize);
    AppendLog(L"[XDR] Recherche XOR 1 octet sur " + Dec(sampleSize) + L" octets...");
    const int totalKeys = 255;
    for (int k = 1; k <= totalKeys; ++k) {
        for (size_t i = 0; i < sampleSize; ++i)
            decrypted[i] = sample[i] ^ (uint8_t)k;
        double e = XdrEntropy(decrypted.data(), sampleSize);
        if (e < bestEntropy) {
            bestEntropy = e;
            bestKey = (uint8_t)k;
            improved = true;
        }
        // Progression + traitement des messages
        if ((k % 16) == 0 || k == totalKeys) {
            int pct = (k * 100) / totalKeys;
            UpdateProgress(10 + (pct * 40 / 100), L"XOR 1 octet " + std::to_wstring(pct) + L"%");
            // Laisser Windows respirer
            MSG msg;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    bool found = improved && (origEntropy - bestEntropy) > 0.01;
    if (found)
        AppendLog(L"[XDR] Clé XOR 1 octet : 0x" + Hex64(bestKey, 2) + L" (entropie=" + std::to_wstring(bestEntropy) + L")");
    else
        AppendLog(L"[XDR] Aucune clé XOR 1 octet significative.");
    return found;
}

// Recherche de clé XOR 2 octets sur un échantillon
static bool FindXorKey2Bytes(const uint8_t* data, size_t size, uint16_t& bestKey, double& bestEntropy) {
    // Échantillon de 512 Ko
    const size_t sampleSize = std::min<size_t>(size, 512 * 1024);
    std::vector<uint8_t> sample(data, data + sampleSize);
    double origEntropy = XdrEntropy(sample.data(), sampleSize);
    bestKey = 0;
    bestEntropy = origEntropy;
    bool found = false;
    AppendLog(L"[XDR] Recherche XOR 16 bits sur " + Dec(sampleSize) + L" octets (65535 clés)...");
    const int totalKeys = 65535;
    for (int k = 1; k <= totalKeys; ++k) {
        // Déchiffrer l'échantillon avec la clé 16 bits (LSB puis MSB selon la position)
        std::vector<uint8_t> decrypted(sampleSize);
        for (size_t i = 0; i < sampleSize; ++i)
            decrypted[i] = sample[i] ^ ((k >> (8 * (i & 1))) & 0xFF);
        double e = XdrEntropy(decrypted.data(), sampleSize);
        if (e < bestEntropy) {
            bestEntropy = e;
            bestKey = (uint16_t)k;
            found = true;
        }
        // Progression toutes les 256 clés
        if ((k % 256) == 0 || k == totalKeys) {
            int pct = (k * 100) / totalKeys;
            UpdateProgress(50 + (pct * 40 / 100), L"XOR 16 bits " + std::to_wstring(pct) + L"%");
            MSG msg;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    if (found && (origEntropy - bestEntropy) > 0.01) {
        AppendLog(L"[XDR] Clé XOR 16 bits trouvée : 0x" + Hex64(bestKey, 4) + L" (entropie=" + std::to_wstring(bestEntropy) + L")");
        return true;
    }
    AppendLog(L"[XDR] Aucune clé XOR 16 bits significative.");
    return false;
}

static bool DetectPackerBySignatures(const uint8_t* data, size_t size, std::wstring& name) {
    // Convertir en vector temporaire pour ContainsAsciiInsensitive ou utiliser une recherche directe.
    // On peut garder la version avec vector pour simplicité.
    std::vector<uint8_t> buf(data, data + size);
    if (ContainsAsciiInsensitive(buf, "Themida")) { name = L"Themida"; return true; }
    if (ContainsAsciiInsensitive(buf, "VMProtect")) { name = L"VMProtect"; return true; }
    if (ContainsAsciiInsensitive(buf, "Enigma")) { name = L"Enigma"; return true; }
    if (ContainsAsciiInsensitive(buf, "MPRESS")) { name = L"MPRESS"; return true; }
    return false;
}

// Sans cette déclaration, MSVC refuse les appels depuis DetectDrm().
static bool ContainsAsciiInsensitive(const std::vector<uint8_t>& data, const char* needle);

// Détection de DRM par signatures (noms de sections, chaînes)
static bool DetectDrm(const PeInfo& pi, const SectionInfo& sec, std::vector<std::wstring>& evidences) {
    bool drm = false;
    std::wstring secNameLower = LowerW(sec.name);
    // Signatures de sections
    if (secNameLower.find(L"themida") != std::wstring::npos ||
        secNameLower.find(L"vmp") != std::wstring::npos ||
        secNameLower.find(L"vmprotect") != std::wstring::npos ||
        secNameLower.find(L"enigma") != std::wstring::npos ||
        secNameLower.find(L"mPRESS") != std::wstring::npos ||
        secNameLower.find(L"aspack") != std::wstring::npos ||
        secNameLower.find(L"pecompact") != std::wstring::npos) {
        drm = true;
        evidences.push_back(L"Section suspecte : " + sec.name);
    }
    // Signatures via imports (ex: VirtualProtect + VirtualAlloc)
    bool hasVProtect = false, hasVAlloc = false;
    for (const auto& im : pi.imports) {
        std::wstring nameLower = LowerW(im.name);
        if (nameLower.find(L"virtualprotect") != std::wstring::npos) hasVProtect = true;
        if (nameLower.find(L"virtualalloc") != std::wstring::npos) hasVAlloc = true;
    }
    if (hasVProtect && hasVAlloc) {
        drm = true;
        evidences.push_back(L"Imports de manipulation mémoire (VirtualProtect + VirtualAlloc)");
    }
    // Vérification des chaînes dans le fichier (signatures packer)
    if (ContainsAsciiInsensitive(g_file, "Themida") ||
        ContainsAsciiInsensitive(g_file, "VMProtect") ||
        ContainsAsciiInsensitive(g_file, "Enigma") ||
        ContainsAsciiInsensitive(g_file, "MPRESS")) {
        drm = true;
        evidences.push_back(L"Signature de packer/protecteur détectée dans les données");
    }
    return drm;
}

// Désassemble un buffer en mémoire
static std::map<uint64_t, std::wstring> DisassembleBuffer(const uint8_t* data, size_t size, uint64_t base, bool is64) {
    return BuildDisassembly(data, size, base, is64);
}

// Fonction principale XDR pour une section – toujours tenter de trouver une clé XOR
static void XdrAnalyzeSection(const SectionInfo& sec, const SectionBytes& bytes, const PeInfo& pi, std::wstringstream& report, bool forceSearch = true) {
    report << L"\n[XDR-Protect] Analyse de la section " << sec.name << L"\n";
    double ent = XdrEntropy(bytes.data, bytes.size);
    report << L"Entropie : " << std::fixed << std::setprecision(3) << ent << L"\n";
    AppendLog(L"[XDR] Analyse de la section " + sec.name + L" - Entropie=" + std::to_wstring(ent));

    std::vector<std::wstring> drmEvidences;
    bool drm = DetectDrm(pi, sec, drmEvidences);
    if (drm) {
        report << L"[!] DRM/protection détecté(e) :\n";
        for (const auto& ev : drmEvidences) report << L"    - " << ev << L"\n";
        AppendLog(L"[XDR] DRM détecté dans " + sec.name);
    }

    std::wstring pname;
    if (DetectPackerBySignatures(bytes.data, bytes.size, pname)) {
        report << L"[PACKER] " << pname << L" détecté dans la section.\n";
    }

    // --- Recherche XOR 1 octet ---
    uint8_t key = 0;
    double bestEnt = ent;
    bool found1 = FindXorKey1Byte(bytes.data, bytes.size, key, bestEnt);
    if (found1) {
        report << L"[+] Clé XOR 1 octet trouvée : 0x" << std::uppercase << std::hex << (int)key
               << L" (entropie après déchiffrement : " << std::fixed << std::setprecision(3) << bestEnt << L")\n";
        AppendLog(L"[XDR] Clé XOR 1 octet trouvée, déchiffrement de la section...");

        // Appliquer la clé pour déchiffrer la section
        std::vector<uint8_t> decrypted(bytes.size);
        for (size_t i = 0; i < bytes.size; ++i) decrypted[i] = bytes.data[i] ^ key;

        // Exporter la section déchiffrée
        std::wstring dir, err;
        if (GetOutputDirChecked(dir, err)) {
            std::wstring outFile = dir + L"\\" + SanitizeFileNamePart(sec.name) + L"_decrypted_xor" + Hex64(key, 2) + L".bin";
            HANDLE h = CreateFileW(outFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(h, decrypted.data(), (DWORD)decrypted.size(), &wr, nullptr);
                CloseHandle(h);
                report << L"[OK] Section déchiffrée (XOR 1 octet) exportée : " << outFile << L"\n";
                AppendLog(L"[XDR] Section déchiffrée exportée : " + outFile);
            } else {
                report << L"[ERREUR] Impossible d'écrire le fichier déchiffré.\n";
                AppendLog(L"[XDR] ERREUR: Impossible d'écrire " + outFile);
            }
        }

        // Désassemblage et décompilation du buffer déchiffré (1 octet)
        uint64_t base = pi.imageBase + sec.va;
        bool is64 = pi.is64;
        AppendLog(L"[XDR] Désassemblage du buffer déchiffré (1 octet)...");
        auto disasmDecrypted = BuildDisassembly(decrypted.data(), decrypted.size(), base, is64);
        if (!disasmDecrypted.empty()) {
            std::wstring dir, err2;
            if (GetOutputDirChecked(dir, err2)) {
                std::wstring asmFile = dir + L"\\" + SanitizeFileNamePart(sec.name) + L"_decrypted_xor1.asm";
                std::wstringstream asmContent;
                for (const auto& [addr, line] : disasmDecrypted) {
                    asmContent << line << L"\r\n";
                }
                WriteUtf8TextFile(asmFile, asmContent.str());
                AppendLog(L"[XDR] ASM déchiffré (XOR1) exporté : " + asmFile);

                auto blocks = BuildBasicBlocks(disasmDecrypted);
                if (!blocks.empty()) {
                    std::wstring pseudo = GeneratePseudoC(blocks, L"zc_" + SanitizeIdentifier(sec.name) + L"_decrypted_xor1", true, true);
                    std::wstring cFile = dir + L"\\" + SanitizeFileNamePart(sec.name) + L"_decrypted_xor1.c";
                    WriteUtf8TextFile(cFile, pseudo);
                    AppendLog(L"[XDR] Pseudo-C déchiffré (XOR1) exporté : " + cFile);
                    report << L"[OK] Pseudo-C généré pour la section déchiffrée (XOR1).\n";
                } else {
                    report << L"[-] Impossible de générer du pseudo-C (aucun bloc de base).\n";
                }
            }
        } else {
            report << L"[-] Aucun désassemblage pour la section déchiffrée (XOR1).\n";
        }
    } else {
        report << L"[-] Aucune clé XOR 1 octet significative trouvée (entropie inchangée).\n";
    }

    // --- Recherche XOR 2 octets (indépendante) ---
    uint16_t key2 = 0;
    double bestEnt2 = ent;
    bool found2 = FindXorKey2Bytes(bytes.data, bytes.size, key2, bestEnt2);
    if (found2) {
        report << L"[+] Clé XOR 2 octets trouvée : 0x" << std::uppercase << std::hex << key2
               << L" (entropie après déchiffrement : " << std::fixed << std::setprecision(3) << bestEnt2 << L")\n";
        // Optionnel : déchiffrer et exporter comme pour le 1 octet (code similaire)
        // Vous pouvez dupliquer le bloc de déchiffrement avec key2 si nécessaire.
        // Pour l'instant, on se contente de l'indiquer dans le rapport.
    } else {
        report << L"[-] Aucune clé XOR 2 octets significative trouvée.\n";
    }
}

static unsigned int __stdcall BruteforceThreadFunc(void* param) {
    _set_se_translator(SeTranslator);
    BruteforceThreadParams* p = (BruteforceThreadParams*)param;
    try {
        std::wstringstream report;
        report << L"\r\n================ BRUTEFORCE ANALYSIS ================\r\n";
        report << L"Désassemblage récursif/linéaire et mode x64 unwind-aware via .pdata quand disponible.\r\n";
        report << L"Mode analyse : COMPLET / exhaustif. Pas de troncature artificielle par défaut ; annulation possible via l'UI.\r\n";
        report << L"Garde-fous : le rapport reste abrégé, mais les grosses sections x64 sont découpées par fonctions .pdata pour éviter le faux code massif.\r\n";

        bool upxFound = false;
        for (const auto& sec : p->pi.sections) {
            if (sec.name == L"UPX0" || sec.name == L"UPX1") upxFound = true;
        }
        if (upxFound) {
            report << L"[AVERTISSEMENT] Le fichier semble compressé avec UPX.\n";
            report << L"Le désassemblage direct sur les sections UPX peut produire peu de code exploitable.\n";
            report << L"Utilisez le bouton 'Décompresser UPX' d'abord si l'objectif est une pseudo-décompilation lisible.\n\n";
        }

        std::wstring outDir, outErr;
        if (GetOutputDirChecked(outDir, outErr)) {
            AppendLog(L"[INFO] Dossier de sortie (bruteforce) : " + outDir);
        } else {
            AppendLog(L"[ERREUR] " + outErr);
            report << L"[ERREUR] " << outErr << L"\r\n";
            p->result = report.str();
            p->finished = true;
            return 0;
        }

        auto iatMap = BuildIatNameMap(p->pi);
        std::vector<AdvancedSectionResult> advancedSections;

        int totalSections = 0;
        for (const auto& sec : p->pi.sections) {
            if (sec.rawSize > 0 || sec.vs > 0) totalSections++;
        }
        if (totalSections == 0) {
            report << L"[WARN] Aucune section avec taille RAW ou virtuelle exploitable.\r\n";
            AppendLog(L"[WARN] Aucune section exploitable pour le bruteforce.");
            p->result = report.str();
            p->finished = true;
            return 0;
        }

        int currentSection = 0;
        int exportedAsm = 0;
        int exportedC = 0;

        for (const auto& sec : p->pi.sections) {
            if (p->cancelled) break;
            if (sec.rawSize == 0 && sec.vs == 0) {
                AppendLog(L"[INFO] Section " + sec.name + L" ignorée : rawSize=0 et virtualSize=0.");
                continue;
            }

            currentSection++;
            bool executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            uint64_t base = p->pi.imageBase + sec.va;

            report << L"\n--- Section " << sec.name << L" ---\n";
            report << L"VA=" << Hex64(sec.va, 8)
                   << L" VS=" << Hex64(sec.vs, 8)
                   << L" RAW=" << Hex64(sec.raw, 8)
                   << L" RS=" << Hex64(sec.rawSize, 8)
                   << L" CH=" << Hex64(sec.characteristics, 8)
                   << L" EXEC=" << (executable ? L"oui" : L"non") << L"\n";

            AppendLog(L"[INFO] Bruteforce section " + sec.name +
                      L" | exec=" + std::wstring(executable ? L"oui" : L"non") +
                      L" | rawSize=" + Dec(sec.rawSize) +
                      L" | virtualSize=" + Dec(sec.vs));

            UpdateProgress((currentSection * 100) / totalSections, L"Bruteforce " + sec.name + L"...");

            SectionBytes bytes;
            std::wstring reason;
            if (!ResolveSectionBytes(sec, bytes, reason)) {
                AppendLog(L"[WARN] Section " + sec.name + L" ignorée proprement : " + reason);
                report << L"Ignorée proprement : " << reason << L"\n";
                continue;
            }

            if (bytes.virtualOnly) {
                AppendLog(L"[WARN] Section " + sec.name + L" : rawSize=0, utilisation de VirtualSize avec buffer zero-fill (" + Dec(bytes.size) + L" octets).");
                report << L"Source octets : section virtuelle sans RAW disque, buffer zero-fill de " << Dec(bytes.size) << L" octets.\n";
            } else {
                AppendLog(L"[INFO] Section " + sec.name + L" : offset disque=" + Hex64(bytes.fileOffset, 8) + L", taille analysée=" + Dec(bytes.size) + L" octets.");
                report << L"Source octets : offset disque=" << Hex64(bytes.fileOffset, 8) << L", taille analysée=" << Dec(bytes.size) << L" octets.\n";
            }
            if (bytes.truncated) {
                AppendLog(L"[WARN] Section " + sec.name + L" tronquée par contrainte mémoire exceptionnelle à " + Dec(bytes.size) + L" octets.");
                report << L"[WARN] Section tronquée par contrainte mémoire exceptionnelle.\n";
            }

            AppendLog(L"[INFO] Recherche de prologues dans " + sec.name + L"...");
            auto funcs = FindFunctionStarts(bytes.data, bytes.size, p->pi.is64);
            size_t prologueCount = funcs.size();
            auto pdataRanges = RuntimeFunctionsForSection(p->pi, sec, bytes.size);
            auto pdataFuncs = RuntimeFunctionStartsForSection(p->pi, sec, bytes.size);
            MergeUniqueStarts(funcs, pdataFuncs);
            report << L"Fonctions détectées : " << funcs.size() << L" (prologues=" << prologueCount << L", .pdata/unwind=" << pdataFuncs.size() << L")\n";
            AppendLog(L"[INFO] " + Dec(funcs.size()) + L" fonctions détectées dans " + sec.name + L" (prologues=" + Dec(prologueCount) + L", .pdata=" + Dec(pdataFuncs.size()) + L")");
            if (!pdataRanges.empty()) {
                ExportRuntimeFunctionIndex(sec.name, pdataRanges);
                report << L"Mode V16 unwind-aware : " << pdataRanges.size() << L" plages de fonctions .pdata utilisées pour éviter le faux linéaire massif.\n";
            }
            for (uint64_t off : funcs) {
                report << L"  Fonction @ " << Hex64(base + off, 8) << L"\n";
            }

            if (!executable && funcs.empty()) {
                report << L"Section non exécutable sans prologue : pas de désassemblage code. Export en tableau de données C.\n";
                AppendLog(L"[INFO] Section " + sec.name + L" non exécutable sans prologue : export en données C, pas en faux ASM.");
                ExportSectionBytesAsDataSource(sec, bytes, false);
                continue;
            }

            std::map<uint64_t, std::wstring> disasmRec;
            std::map<uint64_t, std::wstring> disasmLin;

            if (executable && p->pi.is64 && !pdataRanges.empty()) {
                try {
                    AppendLog(L"[INFO] Désassemblage V16 unwind-aware par fonctions .pdata de " + sec.name + L"...");
                    disasmRec = BuildDisassemblyByRuntimeFunctions(bytes.data, bytes.size, base, sec.va, p->pi.is64, pdataRanges, ZC_MAX_RECURSIVE_INSTRUCTIONS, ZC_RECURSIVE_TIMEOUT_SECONDS);
                    disasmLin = disasmRec;
                    report << L"Instructions désassemblées (unwind-aware .pdata) : " << disasmRec.size() << L"\n";
                    AppendLog(L"[INFO] " + Dec(disasmRec.size()) + L" instructions unwind-aware dans " + sec.name);
                    size_t shownRec = 0;
                    for (const auto& kv : disasmRec) {
                        if (shownRec++ >= ZC_MAX_REPORT_INSTRUCTIONS_PER_SECTION) {
                            report << L"... rapport tronqué, export ASM complet disponible sur disque ...\n";
                            break;
                        }
                        report << kv.second << L"\n";
                    }
                } catch (const std::exception& e) {
                    AppendLog(L"[WARN] Désassemblage unwind-aware échoué pour " + sec.name + L" : " + Utf8ToWide(e.what()));
                    report << L"[WARN] Désassemblage unwind-aware échoué : " << Utf8ToWide(e.what()) << L"\n";
                } catch (...) {
                    AppendLog(L"[WARN] Désassemblage unwind-aware échoué pour " + sec.name + L" : exception non standard.");
                    report << L"[WARN] Désassemblage unwind-aware échoué : exception non standard.\n";
                }
            } else {
                try {
                    AppendLog(L"[INFO] Désassemblage récursif de " + sec.name + L"...");
                    disasmRec = DisassembleRecursive(bytes.data, bytes.size, base, p->pi.is64, &funcs);
                    report << L"Instructions désassemblées (récursif) : " << disasmRec.size() << L"\n";
                    AppendLog(L"[INFO] " + Dec(disasmRec.size()) + L" instructions récursives dans " + sec.name);
                    size_t shownRec = 0;
                    for (const auto& kv : disasmRec) {
                        if (shownRec++ >= ZC_MAX_REPORT_INSTRUCTIONS_PER_SECTION) {
                            report << L"... rapport tronqué, export ASM complet disponible sur disque ...\n";
                            break;
                        }
                        report << kv.second << L"\n";
                    }
                } catch (const std::exception& e) {
                    AppendLog(L"[WARN] Désassemblage récursif échoué pour " + sec.name + L" : " + Utf8ToWide(e.what()));
                    report << L"[WARN] Désassemblage récursif échoué : " << Utf8ToWide(e.what()) << L"\n";
                } catch (...) {
                    AppendLog(L"[WARN] Désassemblage récursif échoué pour " + sec.name + L" : exception non standard.");
                    report << L"[WARN] Désassemblage récursif échoué : exception non standard. Passage au linéaire.\n";
                }

                try {
                    AppendLog(L"[INFO] Désassemblage linéaire de " + sec.name + L"...");
                    disasmLin = BuildDisassembly(bytes.data, bytes.size, base, p->pi.is64, ZC_MAX_LINEAR_INSTRUCTIONS, ZC_LINEAR_TIMEOUT_SECONDS);
                    report << L"Instructions linéaires totales : " << disasmLin.size() << L"\n";
                    AppendLog(L"[INFO] " + Dec(disasmLin.size()) + L" instructions linéaires dans " + sec.name);
                } catch (const std::exception& e) {
                    AppendLog(L"[WARN] Désassemblage linéaire échoué pour " + sec.name + L" : " + Utf8ToWide(e.what()));
                    report << L"[WARN] Désassemblage linéaire échoué : " << Utf8ToWide(e.what()) << L"\n";
                } catch (...) {
                    AppendLog(L"[WARN] Désassemblage linéaire échoué pour " + sec.name + L" : exception non standard.");
                    report << L"[WARN] Désassemblage linéaire échoué : exception non standard.\n";
                }
            }
            disasmRec = AnnotateDisassemblyWithImports(disasmRec, iatMap);
            disasmLin = AnnotateDisassemblyWithImports(disasmLin, iatMap);

            const auto& qualityDisasm = !disasmRec.empty() ? disasmRec : disasmLin;
            CodeQualityMetrics quality = AssessCodeQuality(bytes.data, bytes.size, qualityDisasm, funcs, executable);
            report << L"Qualité code : entropie=" << std::fixed << std::setprecision(3) << quality.entropy
                   << L", DB=" << std::fixed << std::setprecision(2) << (quality.dbRatio * 100.0) << L"%, verdict=" << quality.verdict << L"\n";
            if (quality.probablyPackedOrEncrypted) {
                AppendLog(L"[WARN] " + sec.name + L" ressemble à du code packé/chiffré : pseudo-C désactivé pour éviter un faux résultat.");
                ExportPackedTriageReport(sec, bytes, quality, funcs, qualityDisasm);
                ExportSectionBytesAsDataSource(sec, bytes, true);
                report << L"[WARN] Pseudo-C désactivé : section probablement packée/chiffrée. Voir " << sec.name << L"_packed_triage.md.\n";
                continue;
            }

            if (disasmLin.size() >= ZC_MAX_LINEAR_INSTRUCTIONS) {
                report << L"[WARN] Limite d'instructions linéaires atteinte.\n";
                AppendLog(L"[WARN] Limite d'instructions atteinte pour " + sec.name + L".");
            }
            if (disasmLin.size() > disasmRec.size()) {
                report << L"Des instructions supplémentaires ont été trouvées en linéaire ; elles peuvent contenir des données interprétées comme code.\n";
            }

            if (!disasmLin.empty()) {
                AppendLog(L"[INFO] Export ASM linéaire : " + sec.name + L"_linear.asm");
                ExportDisassemblyToFile(disasmLin, sec.name, L"_linear");
                exportedAsm++;
            } else {
                AppendLog(L"[WARN] Aucun ASM linéaire exporté pour " + sec.name + L" : 0 instruction.");
            }

            if (!disasmRec.empty()) {
                AppendLog(L"[INFO] Export ASM récursif : " + sec.name + L"_recursive.asm");
                ExportDisassemblyToFile(disasmRec, sec.name, L"_recursive");
                exportedAsm++;
            } else {
                AppendLog(L"[WARN] Aucun ASM récursif exporté pour " + sec.name + L" : 0 instruction.");
            }

            const auto& bestDisasm = !disasmRec.empty() ? disasmRec : disasmLin;
            bool shouldGeneratePseudo = executable || !funcs.empty();
            if (!shouldGeneratePseudo) {
                AppendLog(L"[INFO] Pseudo-C non généré pour " + sec.name + L" : section non exécutable sans prologue détecté. Export ASM seulement.");
                report << L"Pseudo-C non généré : section non exécutable sans prologue détecté. Export ASM seulement.\n";
            } else if (!bestDisasm.empty()) {
                try {
                    AppendLog(L"[INFO] Génération pseudo-C : " + sec.name + L"_decompiled.c");
                    auto blocks = BuildBasicBlocks(bestDisasm);
                    auto thunks = DetectImportThunks(bestDisasm, iatMap);
                    auto jumpTables = DetectJumpTables(bestDisasm, iatMap);
                    ExportAdvancedArtifacts(sec.name, bestDisasm, blocks, funcs, base, iatMap, thunks, jumpTables);
                    AdvancedSectionResult ar; ar.name = sec.name; ar.start = base; ar.end = base + bytes.size; ar.blocks = blocks; ar.thunks = thunks; ar.jumpTables = jumpTables; advancedSections.push_back(ar);
                    std::wstring pseudo = GeneratePseudoC(blocks, L"zc_" + SanitizeIdentifier(sec.name) + L"_bruteforce", true, true);
                    if (ExportPseudoCToFile(pseudo, sec.name, L"_decompiled")) {
                        exportedC++;
                    }
                } catch (const std::exception& e) {
                    AppendLog(L"[WARN] Pseudo-C échoué pour " + sec.name + L" : " + Utf8ToWide(e.what()));
                    report << L"[WARN] Pseudo-C échoué : " << Utf8ToWide(e.what()) << L"\n";
                } catch (...) {
                    AppendLog(L"[WARN] Pseudo-C échoué pour " + sec.name + L" : exception non standard.");
                    report << L"[WARN] Pseudo-C échoué : exception non standard.\n";
                }
            } else {
                AppendLog(L"[WARN] Pseudo-C non généré pour " + sec.name + L" : aucun désassemblage exploitable.");
                report << L"Pseudo-C non généré : aucun désassemblage exploitable.\n";
            }

            // ---- Module XDR (privé) ----
            if (p->enableXdr) {
                std::wstringstream xdrReport;
                XdrAnalyzeSection(sec, bytes, p->pi, xdrReport);
                if (!xdrReport.str().empty()) {
                    report << L"\n--- XDR-Protect Report for " << sec.name << L" ---\n";
                    report << xdrReport.str();

                    // Export du rapport XDR complet
                    std::wstring xdrFile = outDir + L"\\" + SanitizeFileNamePart(sec.name) + L"_xdr_report.txt";
                    WriteUtf8TextFile(xdrFile, xdrReport.str());
                    AppendLog(L"[XDR] Rapport exporté : " + xdrFile);

                    // Résumé dans la console
                    std::wstring summary = xdrReport.str();
                    size_t pos = summary.find(L"Entropie");
                    if (pos != std::wstring::npos) {
                        size_t end = summary.find(L'\n', pos);
                        if (end != std::wstring::npos) {
                            AppendLog(L"[XDR] " + summary.substr(pos, end - pos));
                        }
                    }
                    pos = summary.find(L"Clé XOR");
                    if (pos != std::wstring::npos) {
                        size_t end = summary.find(L'\n', pos);
                        if (end != std::wstring::npos) {
                            AppendLog(L"[XDR] " + summary.substr(pos, end - pos));
                        }
                    }
                    pos = summary.find(L"DRM/protection détecté");
                    if (pos != std::wstring::npos) {
                        size_t end = summary.find(L'\n', pos);
                        if (end != std::wstring::npos) {
                            AppendLog(L"[XDR] " + summary.substr(pos, end - pos));
                        }
                    }
                }
            }
            // ---- Fin module XDR ----

        } // fin de la boucle for sur les sections

        if (!advancedSections.empty()) {
            ExportInterSectionCallGraph(p->pi, advancedSections, iatMap);
            report << L"Call graph inter-sections exporté : zenncomp_intersection_callgraph.dot\n";
        }

        report << L"\nExports ASM réalisés : " << exportedAsm << L"\n";
        report << L"Exports pseudo-C réalisés : " << exportedC << L"\n";
        report << L"===============================================================\r\n";
        UpdateProgress(100, L"Bruteforce terminé");
        p->result = report.str();
        p->finished = true;
    } catch (const std::exception& e) {
        p->result = L"[ERREUR] Exception C++ : " + Utf8ToWide(e.what()) + L"\r\n";
        p->finished = true;
    } catch (...) {
        p->result = L"[ERREUR] Exception inconnue.\r\n";
        p->finished = true;
    }
    return 0;
} // Fin de BruteforceThreadFunc

// --------------------------- Fonctions d'interface utilisateur ---------------------------
static void OpenTargetFile() {
    wchar_t fileName[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Executables Windows (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = L"Ouvrir un binaire PE a analyser";

    if (!GetOpenFileNameW(&ofn)) return;

    std::wstring err;
    std::vector<uint8_t> data;
    if (!ReadFileBytes(fileName, data, err)) {
        MessageBoxW(g_hWnd, err.c_str(), L"ZennComp - Erreur", MB_ICONERROR);
        return;
    }

    g_targetPath = fileName;
    g_file.swap(data);
    ClearLog();
    AppendLog(L"[OK] Fichier charge : " + g_targetPath);
    AppendLog(L"[OK] Taille : " + Dec(g_file.size()) + L" octets");
    SetStatus(L"Pret - " + BaseName(g_targetPath));
}

static void DoDumpLive() {
    HWND hBtn = GetDlgItem(g_hWnd, IDC_BTN_DUMPLIVE);
    if (!hBtn) return;

    if (!g_hProcess) {
        MessageBoxW(g_hWnd, L"Aucun processus sélectionné. Utilisez d'abord 'Sélectionner processus' ou 'Lancer EXE'.", L"ZennComp", MB_ICONWARNING);
        return;
    }

    // Si déjà en cours, on arrête
    if (g_dumpLiveRunning) {
        g_dumpLiveRunning = false;
        SetWindowTextW(hBtn, L"DumpLive");
        AppendLog(L"[INFO] Arrêt du DumpLive demandé...");
        SetStatus(L"DumpLive en cours d'arrêt");
        return;
    }

    // Vérifier base/taille
    if (g_imageBase == 0 || g_imageSize == 0) {
        int ret = MessageBoxW(g_hWnd,
            L"Adresse de base ou taille non définies.\nVoulez-vous les saisir manuellement ?",
            L"DumpLive", MB_YESNO);
        if (ret == IDYES) {
            uint64_t base = g_imageBase;
            uint32_t size = g_imageSize;
            if (!ShowBaseSizeDialog(g_hWnd, base, size)) return;
            g_imageBase = base;
            g_imageSize = size;
        } else {
            AppendLog(L"[ERREUR] Image base ou taille manquante.");
            return;
        }
    }

    SetWindowTextW(hBtn, L"Stop DumpLive");
    g_dumpLiveRunning = true;
    SetStatus(L"DumpLive en cours...");

    g_hDumpThread = (HANDLE)_beginthreadex(nullptr, 0, DumpLiveThreadFunc, nullptr, 0, nullptr);
    if (!g_hDumpThread) {
        g_dumpLiveRunning = false;
        SetWindowTextW(hBtn, L"DumpLive");
        AppendLog(L"[ERREUR] Impossible de créer le thread DumpLive.");
        SetStatus(L"Erreur DumpLive");
    }
}

static void DoXdrBruteforce() {
    if (g_file.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier chargé.", L"ZennComp", MB_ICONWARNING);
        return;
    }
    if (g_analysisRunning) {
        MessageBoxW(g_hWnd, L"Une analyse est déjà en cours.", L"ZennComp", MB_ICONINFORMATION);
        return;
    }

    std::wstring err;
    PeInfo pi;
    PeParser parser(g_file);
    if (!parser.Parse(pi, err)) {
        AppendLog(L"[ERREUR] Analyse PE impossible: " + err);
        SetStatus(L"Erreur");
        return;
    }

    g_analysisRunning = true;
    ShowProgressWindow(L"XDR-Protect en cours");

    BruteforceThreadParams params;
    params.pi = pi;
    params.enableXdr = true;   // Activation du module privé

    HANDLE hThread = (HANDLE)_beginthreadex(nullptr, 0, BruteforceThreadFunc, &params, 0, nullptr);
    if (!hThread) {
        CloseProgressWindow();
        g_analysisRunning = false;
        AppendLog(L"[ERREUR] Impossible de lancer le thread XDR.");
        return;
    }

    while (!params.finished) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    CloseProgressWindow();
    g_analysisRunning = false;

    if (params.cancelled) {
        AppendLog(L"[INFO] Analyse XDR annulée.");
        SetStatus(L"Analyse XDR annulée");
        return;
    }

    g_lastReport = params.result;
    AppendLog(params.result);
    SetStatus(L"XDR-Protect terminé - " + BaseName(g_targetPath));
}

static void DoUnpack() {
    if (g_file.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier charge.", L"ZennComp", MB_ICONWARNING);
        return;
    }
    if (!UnpackUPX()) {
        return;
    }
}

static void DoAnalyze(bool strings, bool pseudo, bool disasm = false) {
    if (g_file.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier charge.", L"ZennComp", MB_ICONWARNING);
        return;
    }
    if (g_analysisRunning) {
        MessageBoxW(g_hWnd, L"Une analyse est déjà en cours.", L"ZennComp", MB_ICONINFORMATION);
        return;
    }

    std::wstring err;
    PeInfo pi;
    PeParser parser(g_file);
    if (!parser.Parse(pi, err)) {
        AppendLog(L"[ERREUR] Analyse PE impossible: " + err);
        SetStatus(L"Erreur");
        return;
    }

    g_analysisRunning = true;
    ShowProgressWindow(L"Décompilation en cours");

    StandardAnalysisParams params;
    params.includeStrings = strings;
    params.includePseudo = pseudo;
    params.includeDisasm = disasm;
    params.pi = pi;

    HANDLE hThread = (HANDLE)_beginthreadex(nullptr, 0, StandardAnalysisThreadFunc, &params, 0, nullptr);
    if (!hThread) {
        CloseProgressWindow();
        g_analysisRunning = false;
        AppendLog(L"[ERREUR] Impossible de lancer le thread d'analyse.");
        return;
    }

    while (!params.finished) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    CloseProgressWindow();
    g_analysisRunning = false;

    if (params.cancelled) {
        AppendLog(L"[INFO] Analyse annulee.");
        SetStatus(L"Analyse annulee");
        return;
    }

    g_lastReport = params.result;
    AppendLog(params.result);
    SetStatus(L"Analyse terminee - " + BaseName(g_targetPath));
}

static void DoBruteforce() {
    if (g_file.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier charge.", L"ZennComp", MB_ICONWARNING);
        return;
    }
    if (g_analysisRunning) {
        MessageBoxW(g_hWnd, L"Une analyse est déjà en cours.", L"ZennComp", MB_ICONINFORMATION);
        return;
    }

    std::wstring err;
    PeInfo pi;
    PeParser parser(g_file);
    if (!parser.Parse(pi, err)) {
        AppendLog(L"[ERREUR] Analyse PE impossible: " + err);
        SetStatus(L"Erreur");
        return;
    }

    g_analysisRunning = true;
    ShowProgressWindow(L"Bruteforce en cours");

    BruteforceThreadParams params;
    params.pi = pi;

    HANDLE hThread = (HANDLE)_beginthreadex(nullptr, 0, BruteforceThreadFunc, &params, 0, nullptr);
    if (!hThread) {
        CloseProgressWindow();
        g_analysisRunning = false;
        AppendLog(L"[ERREUR] Impossible de lancer le thread d'analyse.");
        return;
    }

    while (!params.finished) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    CloseProgressWindow();
    g_analysisRunning = false;

    if (params.cancelled) {
        AppendLog(L"[INFO] Analyse annulee.");
        SetStatus(L"Analyse annulee");
        return;
    }

    g_lastReport = params.result;
    AppendLog(params.result);
    SetStatus(L"Bruteforce terminee - " + BaseName(g_targetPath));
}

static void ExportReport() {
    if (g_lastReport.empty()) {
        MessageBoxW(g_hWnd, L"Aucun rapport a exporter. Lance d'abord une analyse.", L"ZennComp", MB_ICONINFORMATION);
        return;
    }

    wchar_t fileName[MAX_PATH] = L"ZennComp_report.txt";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Rapport texte (*.txt)\0*.txt\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrTitle = L"Exporter le rapport ZennComp";
    ofn.lpstrDefExt = L"txt";

    if (!GetSaveFileNameW(&ofn)) return;

    std::string utf8 = WideToUtf8(g_lastReport);
    HANDLE h = CreateFileW(fileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hWnd, L"Impossible de creer le fichier rapport.", L"ZennComp", MB_ICONERROR);
        return;
    }
    const uint8_t bom[3] = {0xEF, 0xBB, 0xBF};
    DWORD wr = 0;
    WriteFile(h, bom, 3, &wr, nullptr);
    WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wr, nullptr);
    CloseHandle(h);
    AppendLog(L"[OK] Rapport exporte : " + std::wstring(fileName));
}


static bool ReadTextFileWide(const std::wstring& path, std::wstring& out, std::wstring& err) {
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, bytes, err)) return false;
    if (bytes.size() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
        std::string utf8((const char*)bytes.data() + 3, bytes.size() - 3);
        out = Utf8ToWide(utf8);
    } else {
        std::string raw((const char*)bytes.data(), bytes.size());
        out = Utf8ToWide(raw);
    }
    return true;
}

static void DoConvertCCpp();
static void DoDecryptorAnalysis();

struct HighlightRange {
    LONG start = 0;
    LONG end = 0;
    COLORREF color = RGB(0, 0, 0);
    bool bold = false;
};

struct EditorLoadResult {
    bool ok = false;
    std::wstring path;
    std::wstring text;
    std::wstring err;
};

struct EditorHighlightResult {
    std::vector<HighlightRange> ranges;
};

struct CodeEditorState {
    HWND hEdit = nullptr;
    HWND hStatus = nullptr;
    int fontHeight = -15;
    std::wstring path;
    std::vector<HighlightRange> pendingHighlight;
    size_t highlightPos = 0;
    bool highlightRunning = false;
};


static bool IsIdentChar(wchar_t c);

static bool HasExtensionLower(const std::wstring& path, const std::wstring& ext) {
    std::wstring lp = LowerW(path);
    if (lp.size() < ext.size()) return false;
    return lp.compare(lp.size() - ext.size(), ext.size(), ext) == 0;
}

static bool IsAsmMnemonicWord(const std::wstring& w) {
    static const wchar_t* words[] = {
        L"mov",L"movzx",L"movsx",L"lea",L"push",L"pop",L"call",L"ret",L"retf",L"jmp",
        L"je",L"jne",L"jz",L"jnz",L"ja",L"jae",L"jb",L"jbe",L"jg",L"jge",L"jl",L"jle",L"js",L"jns",L"jo",L"jno",L"jp",L"jnp",L"jecxz",L"loop",
        L"cmp",L"test",L"add",L"sub",L"mul",L"imul",L"div",L"idiv",L"inc",L"dec",L"neg",
        L"and",L"or",L"xor",L"not",L"shl",L"shr",L"sal",L"sar",L"rol",L"ror",
        L"nop",L"leave",L"int",L"hlt",L"stos",L"lods",L"movs",L"cmps",L"scas",L"rep",L"repe",L"repne",L"db",L"dw",L"dd",L"dq"
    };
    for (auto x : words) if (w == x) return true;
    return false;
}

static bool IsRegisterWord(const std::wstring& w) {
    static const wchar_t* regs[] = {
        L"eax",L"ebx",L"ecx",L"edx",L"esi",L"edi",L"esp",L"ebp",L"eip",
        L"rax",L"rbx",L"rcx",L"rdx",L"rsi",L"rdi",L"rsp",L"rbp",L"rip",
        L"r8",L"r9",L"r10",L"r11",L"r12",L"r13",L"r14",L"r15",
        L"ax",L"bx",L"cx",L"dx",L"al",L"ah",L"bl",L"bh",L"cl",L"ch",L"dl",L"dh",
        L"cs",L"ds",L"es",L"fs",L"gs",L"ss",L"xmm0",L"xmm1",L"xmm2",L"xmm3",L"xmm4",L"xmm5",L"xmm6",L"xmm7"
    };
    for (auto x : regs) if (w == x) return true;
    return false;
}

static bool IsCppKeywordWord(const std::wstring& w) {
    static const wchar_t* kws[] = {
        L"include",L"define",L"ifdef",L"ifndef",L"endif",L"pragma",
        L"namespace",L"class",L"struct",L"public",L"private",L"protected",L"static",L"void",L"int",L"char",L"bool",L"auto",L"const",L"volatile",
        L"extern",L"return",L"if",L"else",L"for",L"while",L"do",L"switch",L"case",L"break",L"continue",L"goto",L"using",L"template",L"typename",
        L"uint8_t",L"uint16_t",L"uint32_t",L"uint64_t",L"size_t",L"std",L"string",L"string_view",L"vector",L"map",L"final"
    };
    for (auto x : kws) if (w == x) return true;
    return false;
}

static void AddHighlightRange(std::vector<HighlightRange>& ranges, size_t start, size_t end, COLORREF color, bool bold = false) {
    if (end <= start || start > (size_t)LONG_MAX || end > (size_t)LONG_MAX) return;
    if (ranges.size() >= 90000) return;
    HighlightRange r; r.start = (LONG)start; r.end = (LONG)end; r.color = color; r.bold = bold;
    ranges.push_back(r);
}

static void ComputeCodeHighlightRanges(const std::wstring& path, const std::wstring& text, std::vector<HighlightRange>& ranges) {
    ranges.clear();
    bool isAsm = HasExtensionLower(path, L".asm");
    bool isC = HasExtensionLower(path, L".c") || HasExtensionLower(path, L".cpp") || HasExtensionLower(path, L".h") || HasExtensionLower(path, L".hpp");
    const size_t maxScan = std::min<size_t>(text.size(), 12 * 1024 * 1024);
    bool atLineStart = true;
    for (size_t i = 0; i < maxScan;) {
        wchar_t c = text[i];
        if (c == L'\r' || c == L'\n') { atLineStart = true; ++i; continue; }

        if (atLineStart) {
            size_t k = i;
            while (k < maxScan && (text[k] == L' ' || text[k] == L'\t')) ++k;
            if (k < maxScan && text[k] == L'#') {
                size_t j = k;
                while (j < maxScan && text[j] != L'\r' && text[j] != L'\n') ++j;
                AddHighlightRange(ranges, k, j, RGB(0, 90, 180), true);
                i = j; atLineStart = false; continue;
            }
        }
        if (!(c == L' ' || c == L'\t')) atLineStart = false;

        if (isC && c == L'/' && i + 1 < maxScan && text[i + 1] == L'/') {
            size_t j = i + 2; while (j < maxScan && text[j] != L'\r' && text[j] != L'\n') ++j;
            AddHighlightRange(ranges, i, j, RGB(0, 128, 0)); i = j; continue;
        }
        if (isC && c == L'/' && i + 1 < maxScan && text[i + 1] == L'*') {
            size_t j = i + 2; while (j + 1 < maxScan && !(text[j] == L'*' && text[j + 1] == L'/')) ++j; if (j + 1 < maxScan) j += 2;
            AddHighlightRange(ranges, i, j, RGB(0, 128, 0)); i = j; continue;
        }
        if (isAsm && c == L';') {
            size_t j = i + 1; while (j < maxScan && text[j] != L'\r' && text[j] != L'\n') ++j;
            AddHighlightRange(ranges, i, j, RGB(0, 128, 0)); i = j; continue;
        }
        if (c == L'\"' || c == L'\'') {
            wchar_t q = c; size_t j = i + 1;
            while (j < maxScan) { if (text[j] == L'\\') { j += 2; continue; } if (text[j] == q) { ++j; break; } if (text[j] == L'\r' || text[j] == L'\n') break; ++j; }
            AddHighlightRange(ranges, i, j, RGB(170, 35, 35)); i = j; continue;
        }
        if (i + 2 < maxScan && text[i] == L'0' && (text[i + 1] == L'x' || text[i + 1] == L'X') && iswxdigit(text[i + 2])) {
            size_t j = i + 2; while (j < maxScan && iswxdigit(text[j])) ++j;
            AddHighlightRange(ranges, i, j, RGB(0, 110, 130)); i = j; continue;
        }
        if (IsIdentChar(c)) {
            size_t j = i + 1; while (j < maxScan && IsIdentChar(text[j])) ++j;
            std::wstring word = text.substr(i, j - i); std::wstring lw = LowerW(word);
            if (word.rfind(L"ZC_", 0) == 0) AddHighlightRange(ranges, i, j, RGB(128, 0, 128), true);
            else if (IsCppKeywordWord(lw)) AddHighlightRange(ranges, i, j, RGB(0, 70, 170), true);
            else if (IsRegisterWord(lw)) AddHighlightRange(ranges, i, j, RGB(150, 80, 0), true);
            else if (IsAsmMnemonicWord(lw)) AddHighlightRange(ranges, i, j, RGB(165, 42, 42), true);
            i = j; continue;
        }
        ++i;
    }
}

static void ApplyRichColorRaw(HWND edit, LONG start, LONG end, COLORREF color, bool bold) {
    if (!edit || end <= start) return;
    SendMessageW(edit, EM_SETSEL, start, end);
    CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf); cf.dwMask = CFM_COLOR | CFM_BOLD; cf.crTextColor = color; cf.dwEffects = bold ? CFE_BOLD : 0;
    SendMessageW(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

static void SaveEditorFile(HWND hwnd) {
    CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!st || !st->hEdit) return;
    int len = GetWindowTextLengthW(st->hEdit);
    std::wstring text((size_t)len, L'\0');
    GetWindowTextW(st->hEdit, &text[0], len + 1);
    text = NormalizeTextForFile(text);
    if (WriteUtf8TextFile(st->path, text)) {
        SetWindowTextW(st->hStatus, L"Sauvegardé.");
        AppendLog(L"[OK] Fichier sauvegardé : " + st->path);
    } else {
        SetWindowTextW(st->hStatus, L"Erreur sauvegarde.");
    }
}


static void EditorSetFont(HWND edit, int height) {
    HFONT mono = CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessageW(edit, WM_SETFONT, (WPARAM)mono, TRUE);
}

static void SetRichColor(HWND edit, LONG start, LONG end, COLORREF color, bool bold) {
    if (!edit || end <= start) return;
    CHARRANGE oldSel{};
    SendMessageW(edit, EM_EXGETSEL, 0, (LPARAM)&oldSel);
    SendMessageW(edit, EM_SETSEL, start, end);
    CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf); cf.dwMask = CFM_COLOR | CFM_BOLD; cf.crTextColor = color; cf.dwEffects = bold ? CFE_BOLD : 0;
    SendMessageW(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(edit, EM_EXSETSEL, 0, (LPARAM)&oldSel);
}

static bool IsIdentChar(wchar_t c) { return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'_'; }

static void ApplyHighlightDefaults(HWND edit) {
    if (!edit) return;
    SendMessageW(edit, EM_SETSEL, 0, -1);
    CHARFORMAT2W def{};
    def.cbSize = sizeof(def);
    def.dwMask = CFM_COLOR | CFM_BOLD | CFM_FACE | CFM_SIZE;
    def.crTextColor = RGB(25, 25, 25);
    def.dwEffects = 0;
    def.yHeight = 180;
    wcscpy_s(def.szFaceName, L"Consolas");
    SendMessageW(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&def);
}

static void ApplyCodeHighlight(HWND edit) {
    if (!edit) return;
    int len = GetWindowTextLengthW(edit);
    if (len <= 0) return;
    std::wstring text((size_t)len, L'\0');
    GetWindowTextW(edit, &text[0], len + 1);
    std::vector<HighlightRange> ranges;
    ComputeCodeHighlightRanges(L".cpp", text, ranges);
    SendMessageW(edit, WM_SETREDRAW, FALSE, 0);
    ApplyHighlightDefaults(edit);
    for (const auto& r : ranges) ApplyRichColorRaw(edit, r.start, r.end, r.color, r.bold);
    SendMessageW(edit, EM_SETSEL, 0, 0);
    SendMessageW(edit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(edit, nullptr, TRUE);
}

static void StartAsyncEditorHighlight(HWND hwnd, const std::wstring& path, const std::wstring& text) {
    if (text.empty()) return;
    ShowProgressWindow(L"Coloration syntaxique");
    UpdateProgress(5, L"Préparation coloration...");
    std::thread([hwnd, path, text]() {
        auto* res = new EditorHighlightResult();
        ComputeCodeHighlightRanges(path, text, res->ranges);
        if (!PostMessageW(hwnd, WM_ZC_EDITOR_HILITE_READY, (WPARAM)res, 0)) delete res;
    }).detach();
}

static void StartAsyncEditorHighlightFromControl(HWND hwnd) {
    CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!st || !st->hEdit) return;
    int len = GetWindowTextLengthW(st->hEdit);
    if (len <= 0) return;
    std::wstring text((size_t)len, L'\0');
    GetWindowTextW(st->hEdit, &text[0], len + 1);
    StartAsyncEditorHighlight(hwnd, st->path, text);
}

static void StartAsyncEditorLoad(HWND hwnd) {
    CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!st) return;
    std::wstring path = st->path;
    ShowProgressWindow(L"Ouverture fichier code");
    UpdateProgress(5, L"Lecture : " + BaseName(path));
    if (st->hStatus) SetWindowTextW(st->hStatus, L"Chargement asynchrone...");
    std::thread([hwnd, path]() {
        auto* res = new EditorLoadResult();
        res->path = path;
        std::wstring text, err;
        UpdateProgress(20, L"Lecture disque...");
        if (ReadTextFileWide(path, text, err)) {
            UpdateProgress(55, L"Normalisation CRLF...");
            res->ok = true;
            res->text = NormalizeTextForWin32Edit(text);
        } else {
            res->ok = false;
            res->err = err;
        }
        if (!PostMessageW(hwnd, WM_ZC_EDITOR_LOADED, (WPARAM)res, 0)) delete res;
    }).detach();
}


static LRESULT CALLBACK CodeEditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        std::wstring* pathPtr = (std::wstring*)cs->lpCreateParams;
        CodeEditorState* st = new CodeEditorState();
        st->path = pathPtr ? *pathPtr : L"";
        delete pathPtr;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)st);

        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP)));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
        HWND saveBtn = CreateWindowW(L"BUTTON", L"Enregistrer", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 10, 8, 110, 28, hwnd, (HMENU)IDC_EDITOR_SAVE, g_hInst, nullptr);
        HWND convertBtn = CreateWindowW(L"BUTTON", L"Convert C/C++", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 128, 8, 125, 28, hwnd, (HMENU)IDC_EDITOR_CONVERT, g_hInst, nullptr);
        HWND recompBtn = CreateWindowW(L"BUTTON", L"Recompiler dossier", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 260, 8, 155, 28, hwnd, (HMENU)IDC_EDITOR_RECOMPILE, g_hInst, nullptr);
        HWND minusBtn = CreateWindowW(L"BUTTON", L"A-", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 422, 8, 45, 28, hwnd, (HMENU)IDC_EDITOR_MINUS, g_hInst, nullptr);
        HWND plusBtn = CreateWindowW(L"BUTTON", L"A+", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 472, 8, 45, 28, hwnd, (HMENU)IDC_EDITOR_PLUS, g_hInst, nullptr);
        (void)saveBtn; (void)convertBtn; (void)recompBtn; (void)minusBtn; (void)plusBtn;
        st->hStatus = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", st->path.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 525, 8, 600, 28, hwnd, nullptr, g_hInst, nullptr);
        st->hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, RICHEDIT_CLASSW, L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL | ES_WANTRETURN | ES_NOHIDESEL, 10, 44, 760, 500, hwnd, (HMENU)IDC_EDITOR_TEXT, g_hInst, nullptr);
        EditorSetFont(st->hEdit, st->fontHeight);
        SendMessageW(st->hEdit, EM_EXLIMITTEXT, 0, 64 * 1024 * 1024);
        int tabStops[1] = { 4 * 4 }; SendMessageW(st->hEdit, EM_SETTABSTOPS, 1, (LPARAM)tabStops);
        SetWindowTextW(st->hEdit, L"/* Chargement asynchrone du fichier... */\r\n");
        StartAsyncEditorLoad(hwnd);
        return 0;
    }
    case WM_ZC_EDITOR_LOADED: {
        std::unique_ptr<EditorLoadResult> res((EditorLoadResult*)wParam);
        CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        CloseProgressWindow();
        if (!st || !st->hEdit || !res) return 0;
        if (res->ok) {
            UpdateProgress(70, L"Affichage...");
            SetWindowTextW(st->hEdit, res->text.c_str());
            SetWindowTextW(st->hStatus, (L"Chargé : " + BaseName(st->path) + L" (" + Dec(res->text.size() / 1024) + L" Ko)").c_str());
            AppendLog(L"[OK] Editeur : fichier chargé en arrière-plan sans coloration syntaxique : " + st->path);
        } else {
            std::wstring msg = L"/* Erreur ouverture : " + res->err + L" */\r\n";
            SetWindowTextW(st->hEdit, msg.c_str());
            SetWindowTextW(st->hStatus, L"Erreur ouverture.");
        }
        return 0;
    }
    case WM_ZC_EDITOR_HILITE_READY: {
        std::unique_ptr<EditorHighlightResult> res((EditorHighlightResult*)wParam);
        CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (!st || !st->hEdit || !res) { CloseProgressWindow(); return 0; }
        st->pendingHighlight.swap(res->ranges);
        st->highlightPos = 0;
        st->highlightRunning = true;
        SendMessageW(st->hEdit, WM_SETREDRAW, FALSE, 0);
        ApplyHighlightDefaults(st->hEdit);
        SetWindowTextW(st->hStatus, (L"Coloration : 0 / " + Dec(st->pendingHighlight.size()) + L" zones").c_str());
        SetTimer(hwnd, IDT_EDITOR_HILITE, 1, nullptr);
        return 0;
    }
    case WM_TIMER: {
        if (wParam != IDT_EDITOR_HILITE) break;
        CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (!st || !st->hEdit || !st->highlightRunning) { KillTimer(hwnd, IDT_EDITOR_HILITE); return 0; }
        const size_t total = st->pendingHighlight.size();
        const size_t step = 700;
        size_t end = std::min(total, st->highlightPos + step);
        for (size_t i = st->highlightPos; i < end; ++i) {
            const auto& r = st->pendingHighlight[i];
            ApplyRichColorRaw(st->hEdit, r.start, r.end, r.color, r.bold);
        }
        st->highlightPos = end;
        int pct = total ? (int)((st->highlightPos * 100) / total) : 100;
        UpdateProgress(pct, L"Coloration syntaxique...");
        SetWindowTextW(st->hStatus, (L"Coloration : " + Dec(st->highlightPos) + L" / " + Dec(total) + L" zones").c_str());
        if (st->highlightPos >= total) {
            KillTimer(hwnd, IDT_EDITOR_HILITE);
            st->highlightRunning = false;
            SendMessageW(st->hEdit, EM_SETSEL, 0, 0);
            SendMessageW(st->hEdit, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(st->hEdit, nullptr, TRUE);
            CloseProgressWindow();
            SetWindowTextW(st->hStatus, (L"Prêt : " + BaseName(st->path)).c_str());
        }
        return 0;
    }
    case WM_SIZE: {
        CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (st) {
            RECT rc; GetClientRect(hwnd, &rc);
            const int editorClientW = static_cast<int>(rc.right - rc.left);
            const int editorClientH = static_cast<int>(rc.bottom - rc.top);
            const int statusW = std::max<int>(100, editorClientW - 635);
            const int editW = std::max<int>(100, editorClientW - 20);
            const int editH = std::max<int>(100, editorClientH - 54);
            MoveWindow(st->hStatus, 625, 8, statusW, 28, TRUE);
            MoveWindow(st->hEdit, 10, 44, editW, editH, TRUE);
        }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_EDITOR_SAVE) { SaveEditorFile(hwnd); return 0; }
        if (LOWORD(wParam) == IDC_EDITOR_CONVERT) { SaveEditorFile(hwnd); SendMessageW(g_hWnd, WM_COMMAND, IDC_BTN_CONVERT, 0); return 0; }
        if (LOWORD(wParam) == IDC_EDITOR_RECOMPILE) { SaveEditorFile(hwnd); SendMessageW(g_hWnd, WM_COMMAND, IDC_BTN_RECOMPILE, 0); return 0; }
        if (LOWORD(wParam) == IDC_EDITOR_HILITE) { MessageBoxW(hwnd, L"Coloration désactivée pour conserver les performances sur les gros fichiers.", L"ZennComp", MB_ICONINFORMATION); return 0; }
        if (LOWORD(wParam) == IDC_EDITOR_PLUS) { CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA); if (st) { st->fontHeight -= 1; EditorSetFont(st->hEdit, st->fontHeight); } return 0; }
        if (LOWORD(wParam) == IDC_EDITOR_MINUS) { CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA); if (st) { st->fontHeight += 1; EditorSetFont(st->hEdit, st->fontHeight); } return 0; }
        break;
    case WM_DESTROY: {
        KillTimer(hwnd, IDT_EDITOR_HILITE);
        CodeEditorState* st = (CodeEditorState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        delete st;
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void OpenCodeEditor(const std::wstring& filePath) {
    if (filePath.empty()) return;
    const wchar_t* cls = L"ZennCompCodeEditor";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.hInstance = g_hInst;
        wc.lpfnWndProc = CodeEditorWndProc;
        wc.lpszClassName = cls;
        wc.hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP));
        wc.hIconSm = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        wc.hCursor = LoadCursorW(nullptr, IDC_IBEAM);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        registered = true;
    }
    std::wstring title = L"ZennComp Code Editor - " + BaseName(filePath);
    CreateWindowExW(0, cls, title.c_str(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    CW_USEDEFAULT, CW_USEDEFAULT, 1000, 720,
                    g_hWnd, nullptr, g_hInst, new std::wstring(filePath));
}

static void ChooseAndOpenDecompiledFile() {
    wchar_t fileName[MAX_PATH]{};
    std::wstring initial = g_lastOutputDir.empty() ? L"" : g_lastOutputDir;
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Code décompilé (*.c;*.cpp;*.h;*.hpp;*.asm;*.txt)\0*.c;*.cpp;*.h;*.hpp;*.asm;*.txt\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = L"Ouvrir un fichier décompilé";
    if (!initial.empty()) ofn.lpstrInitialDir = initial.c_str();
    if (GetOpenFileNameW(&ofn)) OpenCodeEditor(fileName);
}

static void OpenOutputDirectory() {
    std::wstring dir = g_lastOutputDir;
    if (dir.empty()) {
        std::wstring err;
        GetOutputDirChecked(dir, err);
    }
    if (dir.empty()) {
        MessageBoxW(g_hWnd, L"Aucun dossier de sortie connu. Lance une décompilation d'abord.", L"ZennComp", MB_ICONINFORMATION);
        return;
    }
    ShellExecuteW(g_hWnd, L"open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static bool BrowseForFolder(std::wstring& dir, const wchar_t* title) {
    BROWSEINFOW bi{};
    bi.hwndOwner = g_hWnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;
    wchar_t path[MAX_PATH]{};
    bool ok = SHGetPathFromIDListW(pidl, path) != FALSE;
    CoTaskMemFree(pidl);
    if (ok) dir = path;
    return ok;
}

static void FindFilesByMask(const std::wstring& dir, const std::wstring& mask, std::vector<std::wstring>& files) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\" + mask).c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) files.push_back(fd.cFileName); } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}
static std::vector<std::wstring> FindSourceFilesInDirectory(const std::wstring& dir) { std::vector<std::wstring> f; FindFilesByMask(dir,L"*.c",f); FindFilesByMask(dir,L"*.cpp",f); return f; }
static std::vector<std::wstring> FindAsmFilesInDirectory(const std::wstring& dir) { std::vector<std::wstring> f; FindFilesByMask(dir,L"*.asm",f); return f; }

static bool ParseAsmTextToDisasmMap(const std::wstring& text, std::map<uint64_t, std::wstring>& disasm) {
    disasm.clear();
    std::wistringstream in(text);
    std::wstring line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        size_t p = line.find(L"0x");
        if (p == std::wstring::npos) continue;
        wchar_t* endp = nullptr;
        uint64_t a = _wcstoui64(line.c_str() + p, &endp, 16);
        if (endp && endp > line.c_str() + p) disasm[a] = line;
    }
    return !disasm.empty();
}

static std::vector<uint8_t> ExtractDbBytesFromDisassembly(const std::map<uint64_t, std::wstring>& disasm) {
    std::vector<uint8_t> out;
    for (const auto& kv : disasm) {
        std::wstring asmText = StripAddressFromDisasmLine(kv.second);
        std::wstring mn = MnemonicFromAsmText(asmText);
        if (mn != L"db") continue;
        std::wstring ops = StripAsmTrailingComment(OperandsFromAsmText(asmText));
        size_t pos = 0;
        while ((pos = ops.find(L"0x", pos)) != std::wstring::npos) {
            wchar_t* endp = nullptr;
            uint64_t v = _wcstoui64(ops.c_str() + pos, &endp, 16);
            if (endp && endp > ops.c_str() + pos) {
                out.push_back((uint8_t)(v & 0xFF));
                pos = (size_t)(endp - ops.c_str());
            } else {
                pos += 2;
            }
        }
    }
    return out;
}

static bool ConvertAsmFileToSource(const std::wstring& dir, const std::wstring& asmFile, bool cppMode, std::wstring& outPath) {
    std::wstring text, err;
    std::wstring inPath = dir + L"\\" + asmFile;
    if (!ReadTextFileWide(inPath, text, err)) return false;

    std::map<uint64_t, std::wstring> disasm;
    if (!ParseAsmTextToDisasmMap(text, disasm)) return false;

    std::wstring base = asmFile;
    size_t dot = base.find_last_of(L'.');
    if (dot != std::wstring::npos) base = base.substr(0, dot);

    // Si le fichier ASM est majoritairement constitué de db, ce n'est pas du code :
    // on le convertit en tableau C/C++ au lieu de produire un faux pseudo-code.
    if (LooksLikeDataDisassembly(disasm)) {
        std::vector<uint8_t> bytes = ExtractDbBytesFromDisassembly(disasm);
        if (bytes.empty()) return false;
        std::wstring symbol = L"zc_" + SanitizeIdentifier(base);
        std::wstring src = GenerateDataArraySource(symbol, bytes.data(), bytes.size(), cppMode);
        outPath = dir + L"\\" + SanitizeFileNamePart(base + (cppMode ? L"_converted_data.cpp" : L"_converted_data.c"));
        return WriteUtf8TextFile(outPath, NormalizeTextForFile(src));
    }

    auto blocks = BuildBasicBlocks(disasm);
    if (blocks.empty()) return false;

    std::wstring fn = L"zc_" + SanitizeIdentifier(base) + L"_converted";

    std::wstring src;
    if (cppMode) {
        src = GeneratePseudoCpp(blocks, L"ZennComp_" + SanitizeIdentifier(base), fn, false);
    } else {
        src = GeneratePseudoC(blocks, fn, true, false);
    }

    outPath = dir + L"\\" + SanitizeFileNamePart(base + (cppMode ? L"_converted.cpp" : L"_converted.c"));
    return WriteUtf8TextFile(outPath, NormalizeTextForFile(src));
}
static void DoConvertCCpp() {
    std::wstring dir=g_lastOutputDir; if (dir.empty() || MessageBoxW(g_hWnd,(L"Utiliser le dernier dossier de sortie ?\n"+dir).c_str(),L"Convert C/C++",MB_YESNO|MB_ICONQUESTION)!=IDYES) { if(!BrowseForFolder(dir,L"Choisir le répertoire contenant les fichiers ASM décompilés")) return; }
    auto asmFiles=FindAsmFilesInDirectory(dir); if(asmFiles.empty()) { MessageBoxW(g_hWnd,L"Aucun fichier .asm trouvé.",L"Convert C/C++",MB_ICONWARNING); return; }
    int kind=MessageBoxW(g_hWnd,L"Oui = C structuré\nNon = C++ structuré avec namespace + classe + wrapper extern C\nAnnuler = abandonner",L"Convert C/C++",MB_YESNOCANCEL|MB_ICONQUESTION); if(kind==IDCANCEL) return; bool cppMode=(kind==IDNO);
    WriteRuntimeSupportFiles(dir); ShowProgressWindow(L"Conversion ASM vers C/C++"); size_t ok=0; for(size_t i=0;i<asmFiles.size();++i){ UpdateProgress((int)((i*100)/std::max<size_t>(1,asmFiles.size())),L"Conversion "+asmFiles[i]); std::wstring out; if(ConvertAsmFileToSource(dir,asmFiles[i],cppMode,out)){++ok; AppendLog(L"[OK] Converti : "+out);} else AppendLog(L"[WARN] Conversion ignorée : "+asmFiles[i]); }
    UpdateProgress(100,L"Conversion terminée"); CloseProgressWindow(); g_lastOutputDir=dir; MessageBoxW(g_hWnd,(L"Conversion terminée.\nFichiers générés : "+Dec(ok)).c_str(),L"ZennComp",MB_ICONINFORMATION);
}
static void DoRecompile() {
    std::wstring dir = g_lastOutputDir;
    if (dir.empty() || MessageBoxW(g_hWnd, (L"Utiliser le dernier dossier de sortie ?\n" + dir).c_str(), L"Recompiler", MB_YESNO | MB_ICONQUESTION) != IDYES) {
        if (!BrowseForFolder(dir, L"Choisir le répertoire contenant les fichiers .c/.cpp à recompiler")) return;
    }
    auto files = FindSourceFilesInDirectory(dir);
    if (files.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier .c ou .cpp trouvé dans ce répertoire.", L"Recompiler", MB_ICONWARNING);
        return;
    }

    int kind = MessageBoxW(g_hWnd,
        L"Compilation de stub d'audit ZennComp.\n\nOui = EXE\nNon = DLL\nAnnuler = abandonner",
        L"Type de sortie", MB_YESNOCANCEL | MB_ICONQUESTION);
    if (kind == IDCANCEL) return;
    bool dll = (kind == IDNO);

    wchar_t outFile[MAX_PATH]{};
    wcscpy_s(outFile, dll ? L"zenncomp_rebuild.dll" : L"zenncomp_rebuild.exe");
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = dll ? L"DLL Windows (*.dll)\0*.dll\0Tous les fichiers (*.*)\0*.*\0" : L"EXE Windows (*.exe)\0*.exe\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = outFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrTitle = L"Enregistrer le binaire recompilé";
    ofn.lpstrDefExt = dll ? L"dll" : L"exe";
    if (!GetSaveFileNameW(&ofn)) return;

    WriteRuntimeSupportFiles(dir);

    std::wstring bat = dir + L"\\zenncomp_build_temp.bat";
    std::wstring log = dir + L"\\zenncomp_build.log";
    std::wstringstream b;
    b << L"@echo off\r\n";
    b << L"setlocal EnableDelayedExpansion\r\n";
    b << L"cd /d \"" << dir << L"\"\r\n";
    b << L"echo === ZennComp build === > zenncomp_build.log\r\n";
    b << L"set SRC=\r\n";
    b << L"for %%F in (*.c *.cpp) do set SRC=!SRC! \"%%F\"\r\n";
    b << L"where cl.exe >nul 2>nul\r\n";
    b << L"if %ERRORLEVEL% EQU 0 (\r\n";
    if (dll) b << L"  cl.exe /nologo /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS /LD !SRC! /link /OUT:\"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    else b << L"  cl.exe /nologo /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS !SRC! /link /OUT:\"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    b << L"  exit /b %ERRORLEVEL%\r\n";
    b << L")\r\n";
    b << L"where g++.exe >nul 2>nul\r\n";
    b << L"if %ERRORLEVEL% EQU 0 (\r\n";
    if (dll) b << L"  g++.exe -std=c++17 -O2 -Wall -shared !SRC! -o \"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    else b << L"  g++.exe -std=c++17 -O2 -Wall !SRC! -o \"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    b << L"  exit /b %ERRORLEVEL%\r\n";
    b << L")\r\n";
    b << L"where gcc.exe >nul 2>nul\r\n";
    b << L"if %ERRORLEVEL% EQU 0 (\r\n";
    if (dll) b << L"  gcc.exe -std=c99 -O2 -Wall -shared *.c -o \"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    else b << L"  gcc.exe -std=c99 -O2 -Wall *.c -o \"" << outFile << L"\" >> zenncomp_build.log 2>&1\r\n";
    b << L"  exit /b %ERRORLEVEL%\r\n";
    b << L")\r\n";
    b << L"echo Aucun compilateur trouvé. Lance ZennComp depuis le Developer Command Prompt VS ou installe MinGW/g++. >> zenncomp_build.log\r\n";
    b << L"exit /b 9009\r\n";
    if (!WriteUtf8TextFile(bat, b.str(), false)) return;

    std::wstring msg = L"Compiler " + Dec(files.size()) + L" fichier(s) .c/.cpp depuis :\n" + dir + L"\n\nSortie :\n" + outFile;
    if (MessageBoxW(g_hWnd, msg.c_str(), L"Confirmer compilation", MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"cmd.exe /C call \"" + bat + L"\"";
    AppendLog(L"[INFO] Compilation : " + cmd);
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, dir.c_str(), &si, &pi)) {
        AppendLog(L"[ERREUR] Impossible de lancer la compilation. Code Win32=" + Dec(GetLastError()));
        return;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wstring buildLog, err;
    if (ReadTextFileWide(log, buildLog, err)) AppendLog(buildLog);
    if (exitCode == 0) {
        AppendLog(L"[OK] Compilation terminée : " + std::wstring(outFile));
        MessageBoxW(g_hWnd, (L"Compilation terminée :\n" + std::wstring(outFile)).c_str(), L"ZennComp", MB_ICONINFORMATION);
    } else {
        AppendLog(L"[ERREUR] Compilation échouée. Code=" + Dec(exitCode) + L". Voir zenncomp_build.log");
        MessageBoxW(g_hWnd, (L"Compilation échouée.\nLog : " + log).c_str(), L"ZennComp", MB_ICONERROR);
    }
}


static bool ContainsAsciiInsensitive(const std::vector<uint8_t>& data, const char* needle) {
    if (!needle || !*needle || data.empty()) return false; size_t n=strlen(needle); if(n>data.size()) return false;
    for(size_t i=0;i+n<=data.size();++i){ bool ok=true; for(size_t j=0;j<n;++j){ unsigned char a=data[i+j],b=(unsigned char)needle[j]; if(a>='A'&&a<='Z')a=(unsigned char)(a-'A'+'a'); if(b>='A'&&b<='Z')b=(unsigned char)(b-'A'+'a'); if(a!=b){ok=false;break;} } if(ok)return true; } return false;
}
static double PrintableRatioXor(const uint8_t* data, size_t len, uint8_t key) { if(!data||!len)return 0.0; size_t p=0; for(size_t i=0;i<len;++i){uint8_t c=data[i]^key; if(c==0||c==9||c==10||c==13||(c>=0x20&&c<=0x7E))p++;} return (double)p/(double)len; }
static void DoDecryptorAnalysis() {
    if(g_file.empty()||g_targetPath.empty()){MessageBoxW(g_hWnd,L"Charge d'abord un EXE/DLL/SYS.",L"Décryptor statique",MB_ICONINFORMATION);return;} PeInfo pi; std::wstring err; PeParser parser(g_file); if(!parser.Parse(pi,err)){MessageBoxW(g_hWnd,(L"PE invalide : "+err).c_str(),L"Décryptor statique",MB_ICONERROR);return;} std::wstring dir; if(!GetOutputDirChecked(dir,err)){MessageBoxW(g_hWnd,err.c_str(),L"Décryptor statique",MB_ICONERROR);return;}
    ShowProgressWindow(L"Décryptor statique / détection packer"); std::wstringstream report; report<<L"================ ZennComp - Analyse crypto/packer statique ================\r\n"; report<<L"Fichier : "<<g_targetPath<<L"\r\n"; report<<L"Mode    : analyse statique, aucune exécution, pas de contournement DRM/licence.\r\n\r\n";
    std::vector<const char*> sigs={"UPX","Themida","VMProtect","Enigma","MPRESS","ASPack","PECompact","Nullsoft","NSIS"}; report<<L"[Signatures packer/installeur]\r\n"; for(const char* sig:sigs) report<<L" - "<<Utf8ToWide(sig)<<L" : "<<(ContainsAsciiInsensitive(g_file,sig)?L"OUI":L"non")<<L"\r\n"; report<<L"\r\n[Sections]\r\n";
    size_t suspicious=0; for(size_t i=0;i<pi.sections.size();++i){const auto& sec=pi.sections[i]; UpdateProgress((int)((i*100)/std::max<size_t>(1,pi.sections.size())),L"Analyse crypto "+sec.name); SectionBytes bytes; std::wstring reason; if(!ResolveSectionBytes(sec,bytes,reason)){report<<L" - "<<sec.name<<L" : ignorée ("<<reason<<L")\r\n";continue;} double e=Entropy(bytes.data,bytes.size); bool high=e>=7.20&&bytes.size>=512, very=e>=7.75&&bytes.size>=512; if(high)suspicious++; report<<L" - "<<sec.name<<L" | taille="<<Dec(bytes.size)<<L" | entropie="<<std::fixed<<std::setprecision(3)<<e<<L" | verdict="<<(very?L"chiffrement/compression probable":(high?L"packer/chiffrement possible":L"normal"))<<L"\r\n"; size_t sample=std::min<size_t>(bytes.size,65536); int xorShown=0; if(high){for(int k=1;k<256 && xorShown<5;++k){double sc=PrintableRatioXor(bytes.data,sample,(uint8_t)k); if(sc>0.95){ report<<L"     XOR 1-octet candidat key="<<Hex64((uint8_t)k,2)<<L" score_printable="<<std::fixed<<std::setprecision(2)<<(sc*100.0)<<L"%\r\n"; xorShown++; }}}}
    report<<L"\r\n[Conclusion]\r\n"; if(suspicious) report<<L" - "<<Dec(suspicious)<<L" section(s) à entropie élevée : compression, packing ou chiffrement possible.\r\n - Recherche limitée aux indices statiques et XOR simple ; pas de cassage AES/RSA, mot de passe, licence ou protection tierce.\r\n"; else report<<L" - Aucune section fortement chiffrée/compressée selon les heuristiques d'entropie.\r\n"; report<<L"\r\n[FIN]\r\n";
    std::wstring out=dir+L"\\zenncomp_crypto_analysis.txt"; WriteUtf8TextFile(out,report.str()); AppendLog(report.str()); AppendLog(L"[OK] Rapport crypto/packer exporté : "+out); UpdateProgress(100,L"Analyse crypto terminée"); CloseProgressWindow();
}


static void DoRunTarget() {
    if (g_file.empty() || g_targetPath.empty()) {
        MessageBoxW(g_hWnd, L"Aucun fichier chargé.", L"ZennComp", MB_ICONWARNING);
        return;
    }
    PeInfo pi;
    std::wstring err;
    PeParser parser(g_file);
    if (!parser.Parse(pi, err)) {
        AppendLog(L"[ERREUR] Analyse PE impossible: " + err);
        return;
    }
    g_imageBase = pi.imageBase;
    uint32_t maxEnd = 0;
    for (const auto& sec : pi.sections) {
        uint32_t end = sec.va + std::max(sec.vs, sec.rawSize);
        if (end > maxEnd) maxEnd = end;
    }
    g_imageSize = maxEnd;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION piProc;
    if (!CreateProcessW(g_targetPath.c_str(), NULL, NULL, NULL, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &piProc)) {
        AppendLog(L"[ERREUR] Impossible de lancer le processus. Code Win32=" + Dec(GetLastError()));
        return;
    }
    g_hProcess = piProc.hProcess;
    g_dwProcessId = piProc.dwProcessId;
    g_hThread = piProc.hThread;
    CloseHandle(g_hThread);
    g_hThread = NULL;
    AppendLog(L"[INFO] Processus lancé (PID=" + Dec(g_dwProcessId) + L", ImageBase=0x" + Hex64(g_imageBase, 16) + L", Taille=" + Dec(g_imageSize) + L")");
    SetStatus(L"Processus en cours - " + BaseName(g_targetPath));
}

static LRESULT CALLBACK BaseSizeDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    BaseSizeData* data = (BaseSizeData*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        data = (BaseSizeData*)cs->lpCreateParams;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)data);

        // Création des contrôles
        HWND hLabelBase = CreateWindowW(L"STATIC", L"Adresse de base (hex) :",
                                        WS_CHILD | WS_VISIBLE,
                                        10, 10, 150, 20, hDlg, nullptr, g_hInst, nullptr);
        HWND hBaseEdit = CreateWindowW(L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER,
                                       170, 10, 200, 20, hDlg, (HMENU)1001, g_hInst, nullptr);
        SendMessageW(hBaseEdit, EM_SETLIMITTEXT, 16, 0);
        wchar_t baseStr[64];
        wsprintfW(baseStr, L"%llX", data->base ? data->base : 0x140000000ULL);
        SetWindowTextW(hBaseEdit, baseStr);

        HWND hLabelSize = CreateWindowW(L"STATIC", L"Taille (octets, hex ou décimal) :",
                                        WS_CHILD | WS_VISIBLE,
                                        10, 40, 200, 20, hDlg, nullptr, g_hInst, nullptr);
        HWND hSizeEdit = CreateWindowW(L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER,
                                       220, 40, 150, 20, hDlg, (HMENU)1002, g_hInst, nullptr);
        SendMessageW(hSizeEdit, EM_SETLIMITTEXT, 10, 0);
        wchar_t sizeStr[64];
        wsprintfW(sizeStr, L"%u", data->size ? data->size : 0x1000000);
        SetWindowTextW(hSizeEdit, sizeStr);

        HWND hOK = CreateWindowW(L"BUTTON", L"OK",
                                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 120, 80, 80, 25, hDlg, (HMENU)IDOK, g_hInst, nullptr);
        HWND hCancel = CreateWindowW(L"BUTTON", L"Annuler",
                                     WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                     220, 80, 80, 25, hDlg, (HMENU)IDCANCEL, g_hInst, nullptr);

        // Appliquer la police système
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageW(hBaseEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hSizeEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hOK, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hCancel, WM_SETFONT, (WPARAM)hFont, TRUE);

        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK) {
            HWND hBaseEdit = GetDlgItem(hDlg, 1001);
            HWND hSizeEdit = GetDlgItem(hDlg, 1002);
            wchar_t baseStr[64], sizeStr[64];
            GetWindowTextW(hBaseEdit, baseStr, 64);
            GetWindowTextW(hSizeEdit, sizeStr, 64);

            uint64_t base = 0;
            uint32_t size = 0;
            wchar_t* endp = nullptr;
            base = wcstoull(baseStr, &endp, 16);
            if (endp == baseStr) {
                MessageBoxW(hDlg, L"Adresse de base invalide (format hexadécimal attendu).", L"Erreur", MB_ICONERROR);
                return 0;
            }
            unsigned long tmp = wcstoul(sizeStr, &endp, 0);
            if (endp == sizeStr) {
                MessageBoxW(hDlg, L"Taille invalide (nombre décimal ou hexadécimal attendu).", L"Erreur", MB_ICONERROR);
                return 0;
            }
            size = (uint32_t)tmp;
            if (base == 0 || size == 0) {
                MessageBoxW(hDlg, L"L'adresse et la taille doivent être > 0.", L"Erreur", MB_ICONERROR);
                return 0;
            }
            if (data) {
                data->base = base;
                data->size = size;
                data->ok = true;
            }
            DestroyWindow(hDlg);
        } else if (id == IDCANCEL) {
            if (data) data->ok = false;
            DestroyWindow(hDlg);
        }
        return 0;
    }
    case WM_DESTROY: {
        // PostQuitMessage(0); 
        return 0;
    }
    }
    return DefWindowProcW(hDlg, msg, wParam, lParam);
}

static bool ShowBaseSizeDialog(HWND hwndOwner, uint64_t& base, uint32_t& size) {
    BaseSizeData data;
    data.base = base ? base : 0x140000000ULL;
    data.size = size ? size : 0x1000000;
    data.ok = false;

    const wchar_t* dlgClass = L"ZennCompBaseSizeDialog";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.hInstance = g_hInst;
        wc.lpfnWndProc = BaseSizeDlgProc;
        wc.lpszClassName = dlgClass;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    // Utilisation de WS_OVERLAPPEDWINDOW pour une fenêtre redimensionnable
    HWND hDlg = CreateWindowExW(0, dlgClass, L"Saisie manuelle",
                                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 460, 180,
                                hwndOwner, nullptr, g_hInst, &data);
    if (!hDlg) return false;

    EnableWindow(hwndOwner, FALSE);

    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    EnableWindow(hwndOwner, TRUE);
    SetForegroundWindow(hwndOwner);

    if (data.ok) {
        base = data.base;
        size = data.size;
        return true;
    }
    return false;
}

static void DoDumpMemory() {
    if (!g_hProcess) {
        MessageBoxW(g_hWnd, L"Aucun processus sélectionné. Utilisez 'Sélectionner processus' d'abord.", L"ZennComp", MB_ICONWARNING);
        return;
    }

    // Si l'image base ou la taille sont inconnues, on demande à l'utilisateur
    if (g_imageBase == 0 || g_imageSize == 0) {
        int ret = MessageBoxW(g_hWnd,
            L"Adresse de base ou taille non définies.\nVoulez-vous les saisir manuellement ?",
            L"Plage mémoire", MB_YESNO);
        if (ret == IDYES) {
            uint64_t base = g_imageBase;
            uint32_t size = g_imageSize;
            if (!ShowBaseSizeDialog(g_hWnd, base, size)) {
                AppendLog(L"[INFO] Dump annulé par l'utilisateur.");
                return;
            }
            g_imageBase = base;
            g_imageSize = size;
        } else {
            AppendLog(L"[ERREUR] Image base ou taille manquantes, dump impossible.");
            return;
        }
    }

    // Choix du fichier de sortie
    wchar_t fileName[MAX_PATH] = L"memory_dump.bin";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Fichier dump (*.bin;*.dmp)\0*.bin;*.dmp\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrTitle = L"Enregistrer le dump mémoire";
    ofn.lpstrDefExt = L"bin";
    if (!GetSaveFileNameW(&ofn)) {
        AppendLog(L"[INFO] Sauvegarde annulée.");
        return;
    }

    // Lecture mémoire par régions
    std::vector<uint8_t> buffer;
    uint64_t addr = g_imageBase;
    uint64_t endAddr = g_imageBase + g_imageSize;
    MEMORY_BASIC_INFORMATION mbi;
    size_t totalRead = 0;

    AppendLog(L"[INFO] Dump mémoire de 0x" + Hex64(addr, 16) + L" à 0x" + Hex64(endAddr, 16) + L" (" + Dec(g_imageSize) + L" octets)");

    while (addr < endAddr) {
        SIZE_T result = VirtualQueryEx(g_hProcess, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (result == 0) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER || err == ERROR_PARTIAL_COPY) {
                AppendLog(L"[AVERTISSEMENT] VirtualQueryEx a échoué à 0x" + Hex64(addr, 16) + L", on avance d'une page.");
                addr += 0x1000;
                continue;
            } else {
                AppendLog(L"[AVERTISSEMENT] VirtualQueryEx a échoué à 0x" + Hex64(addr, 16) + L" (err=" + Dec(err) + L"), arrêt de la lecture.");
                break;
            }
        }

        uint64_t regionEnd = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > endAddr) regionEnd = endAddr;

        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_READONLY | PAGE_EXECUTE_READWRITE))) {
            SIZE_T regionSize = (SIZE_T)(regionEnd - addr);
            if (regionSize > 0) {
                size_t oldSize = buffer.size();
                buffer.resize(oldSize + regionSize);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(g_hProcess, (LPCVOID)addr, buffer.data() + oldSize, regionSize, &bytesRead)) {
                    totalRead += bytesRead;
                    if (bytesRead < regionSize) {
                        buffer.resize(oldSize + bytesRead);
                        AppendLog(L"[AVERTISSEMENT] Lecture partielle de la région 0x" + Hex64(addr, 16) + L" (" + Dec(bytesRead) + L" / " + Dec(regionSize) + L" octets)");
                    }
                    AppendLog(L"[INFO] Lecture région : 0x" + Hex64(addr, 16) + L" (" + Dec(bytesRead) + L" octets)");
                } else {
                    DWORD err = GetLastError();
                    if (err == ERROR_PARTIAL_COPY) {
                        // Lecture octet par octet
                        size_t pos = 0;
                        size_t oldSize2 = buffer.size();
                        buffer.resize(oldSize2 + regionSize);
                        size_t bytesRead2 = 0;
                        while (pos < regionSize) {
                            uint8_t byte;
                            SIZE_T one = 0;
                            if (ReadProcessMemory(g_hProcess, (LPCVOID)(addr + pos), &byte, 1, &one) && one == 1) {
                                buffer[oldSize2 + pos] = byte;
                                bytesRead2++;
                            }
                            pos++;
                        }
                        if (bytesRead2 > 0) {
                            buffer.resize(oldSize2 + bytesRead2);
                            totalRead += bytesRead2;
                            AppendLog(L"[INFO] Lecture partielle (octet par octet) de la région 0x" + Hex64(addr, 16) + L" (" + Dec(bytesRead2) + L" / " + Dec(regionSize) + L" octets)");
                        } else {
                            buffer.resize(oldSize2);
                            AppendLog(L"[AVERTISSEMENT] Aucune donnée lue dans la région 0x" + Hex64(addr, 16));
                        }
                    } else {
                        AppendLog(L"[AVERTISSEMENT] Échec de lecture à 0x" + Hex64(addr, 16) + L", erreur " + Dec(err));
                    }
                }
            }
        }
        addr = regionEnd;
    }

    if (buffer.empty()) {
        AppendLog(L"[ERREUR] Aucune donnée lue.");
        MessageBoxW(g_hWnd, L"Impossible de lire la mémoire du processus. Vérifiez l'adresse de base et les permissions.", L"ZennComp", MB_ICONERROR);
        return;
    }

    totalRead = buffer.size();
    AppendLog(L"[INFO] Lecture totale : " + Dec(totalRead) + L" octets.");

    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        AppendLog(L"[ERREUR] Impossible de créer le fichier dump. Code Win32=" + Dec(GetLastError()));
        return;
    }
    DWORD written = 0;
    WriteFile(hFile, buffer.data(), (DWORD)buffer.size(), &written, nullptr);
    CloseHandle(hFile);
    AppendLog(L"[OK] Dump mémoire sauvegardé : " + std::wstring(fileName) + L" (" + Dec(buffer.size()) + L" octets)");
    SetStatus(L"Dump mémoire effectué - " + std::wstring(fileName));

    // Tentative de déchiffrement automatique si entropie élevée (optionnel)
    double ent = Entropy(buffer.data(), buffer.size());
    if (ent > 7.5) {
        AppendLog(L"[XDR] Entropie élevée (" + std::to_wstring(ent) + L"), tentative de déchiffrement XOR automatique...");
        uint8_t key1 = 0; double bestEnt1 = ent;
        if (FindXorKey1Byte(buffer.data(), buffer.size(), key1, bestEnt1)) {
            AppendLog(L"[XDR] Clé XOR 1 octet trouvée : 0x" + Hex64(key1, 2) + L" (entropie=" + std::to_wstring(bestEnt1) + L")");
            std::vector<uint8_t> decrypted(buffer.size());
            for (size_t i = 0; i < buffer.size(); ++i) decrypted[i] = buffer[i] ^ key1;
            std::wstring decFile = std::wstring(fileName) + L"_decrypted_xor1.bin";
            HANDLE hDec = CreateFileW(decFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDec != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hDec, decrypted.data(), (DWORD)decrypted.size(), &wr, nullptr);
                CloseHandle(hDec);
                AppendLog(L"[OK] Fichier déchiffré (XOR1) : " + decFile);
            }
        }
        uint16_t key2 = 0; double bestEnt2 = ent;
        if (FindXorKey2Bytes(buffer.data(), buffer.size(), key2, bestEnt2)) {
            AppendLog(L"[XDR] Clé XOR 2 octets trouvée : 0x" + Hex64(key2, 4) + L" (entropie=" + std::to_wstring(bestEnt2) + L")");
            std::vector<uint8_t> decrypted(buffer.size());
            for (size_t i = 0; i < buffer.size(); ++i)
                decrypted[i] = buffer[i] ^ ((key2 >> (8 * (i & 1))) & 0xFF);
            std::wstring decFile = std::wstring(fileName) + L"_decrypted_xor2.bin";
            HANDLE hDec = CreateFileW(decFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDec != INVALID_HANDLE_VALUE) {
                DWORD wr2 = 0;
                WriteFile(hDec, decrypted.data(), (DWORD)decrypted.size(), &wr2, nullptr);
                CloseHandle(hDec);
                AppendLog(L"[OK] Fichier déchiffré (XOR2) : " + decFile);
            }
        }
    }
}

static void DoLoadDump() {
    wchar_t fileName[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Dump mémoire (*.bin;*.dmp)\0*.bin;*.dmp\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = L"Charger un dump mémoire";
    if (!GetOpenFileNameW(&ofn)) return;

    std::wstring err;
    std::vector<uint8_t> data;
    if (!ReadFileBytes(fileName, data, err)) {
        MessageBoxW(g_hWnd, err.c_str(), L"ZennComp - Erreur", MB_ICONERROR);
        return;
    }
    g_targetPath = fileName;
    g_file.swap(data);
    ClearLog();
    AppendLog(L"[OK] Dump chargé : " + g_targetPath);
    AppendLog(L"[OK] Taille : " + Dec(g_file.size()) + L" octets");
    SetStatus(L"Dump chargé - " + BaseName(g_targetPath));
    // Réinitialiser les infos de processus (le dump n'est pas un EXE)
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        g_dwProcessId = 0;
    }
    g_imageBase = 0;
    g_imageSize = 0;
}

// Remplit la liste des processus en cours
static std::vector<ProcessEntry> GetRunningProcesses() {
    std::vector<ProcessEntry> list;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            ProcessEntry entry;
            entry.pid = pe.th32ProcessID;
            entry.name = pe.szExeFile;
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                wchar_t path[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                    entry.exePath = path;
                }
                CloseHandle(hProcess);
            }
            list.push_back(entry);
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return list;
}

static LRESULT CALLBACK ProcessSelectorProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ProcessSelectorData* data = (ProcessSelectorData*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        data = (ProcessSelectorData*)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)data);

        HWND hList = CreateWindowW(L"LISTBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | WS_TABSTOP,
            10, 10, 460, 280,
            hwnd, (HMENU)1001, g_hInst, nullptr);
        SendMessageW(hList, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        HWND hBtnOK = CreateWindowW(L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            180, 310, 80, 25,
            hwnd, (HMENU)IDOK, g_hInst, nullptr);
        HWND hBtnCancel = CreateWindowW(L"BUTTON", L"Annuler",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            280, 310, 80, 25,
            hwnd, (HMENU)IDCANCEL, g_hInst, nullptr);

        for (const auto& p : data->processes) {
            std::wstring item = L"PID: " + Dec(p.pid) + L" - " + p.name + L" (" + p.exePath + L")";
            SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item.c_str());
        }
        return 0;
    }
    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        HWND hList = GetDlgItem(hwnd, 1001);
        if (hList) {
            int listH = rc.bottom - 60;
            MoveWindow(hList, 10, 10, rc.right - 20, listH, TRUE);
        }
        HWND hOK = GetDlgItem(hwnd, IDOK);
        HWND hCancel = GetDlgItem(hwnd, IDCANCEL);
        if (hOK && hCancel) {
            int y = rc.bottom - 35;
            MoveWindow(hOK, (rc.right / 2) - 90, y, 80, 25, TRUE);
            MoveWindow(hCancel, (rc.right / 2) + 10, y, 80, 25, TRUE);
        }
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK) {
            HWND hList = GetDlgItem(hwnd, 1001);
            int sel = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && data && sel < (int)data->processes.size()) {
                data->selectedPid = data->processes[sel].pid;
                DestroyWindow(hwnd);
            }
        } else if (id == IDCANCEL) {
            if (data) data->selectedPid = 0;
            DestroyWindow(hwnd);
        } else if (id == 1001 && HIWORD(wParam) == LBN_DBLCLK) {
            SendMessageW(hwnd, WM_COMMAND, IDOK, 0);
        }
        return 0;
    }
    case WM_DESTROY:
        // NE PAS appeler PostQuitMessage ici
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Boîte de dialogue pour sélectionner un processus
static DWORD SelectProcessDialog(HWND hwndOwner) {
    ProcessSelectorData data;
    data.processes = GetRunningProcesses();
    if (data.processes.empty()) {
        MessageBoxW(hwndOwner, L"Aucun processus trouvé.", L"Sélection", MB_ICONINFORMATION);
        return 0;
    }

    // Enregistrement de la classe (une seule fois)
    const wchar_t* dlgClass = L"ZennCompProcessSelector";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.hInstance = g_hInst;
        wc.lpfnWndProc = ProcessSelectorProc;
        wc.lpszClassName = dlgClass;
        wc.hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP));
        wc.hIconSm = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    // Création de la fenêtre (redimensionnable)
    HWND hDlg = CreateWindowExW(0, dlgClass, L"Sélectionner un processus",
                                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
                                hwndOwner, nullptr, g_hInst, &data);
    if (!hDlg) return 0;

    // Rendre la fenêtre modale (désactiver le parent)
    EnableWindow(hwndOwner, FALSE);

    // Boucle de messages propre
    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // Réactiver le parent
    EnableWindow(hwndOwner, TRUE);
    SetForegroundWindow(hwndOwner);

    return data.selectedPid;
}

// Fonction appelée par le bouton "Sélectionner processus"
static void DoSelectProcess() {
    DWORD pid = SelectProcessDialog(g_hWnd);
    if (pid == 0) return;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        AppendLog(L"[ERREUR] Impossible d'ouvrir le processus PID=" + Dec(pid) + L". Code Win32=" + Dec(GetLastError()));
        return;
    }

    if (g_hProcess) CloseHandle(g_hProcess);
    g_hProcess = hProcess;
    g_dwProcessId = pid;

    // Essayer de récupérer l'image base à partir du PE chargé, sinon automatiquement
    if (!g_file.empty()) {
        PeInfo pi;
        std::wstring err;
        PeParser parser(g_file);
        if (parser.Parse(pi, err)) {
            g_imageBase = pi.imageBase;
            uint32_t maxEnd = 0;
            for (const auto& sec : pi.sections) {
                uint32_t end = sec.va + std::max(sec.vs, sec.rawSize);
                if (end > maxEnd) maxEnd = end;
            }
            g_imageSize = maxEnd;
            AppendLog(L"[INFO] Processus sélectionné PID=" + Dec(pid) + L", ImageBase=0x" + Hex64(g_imageBase, 16) + L", Taille=" + Dec(g_imageSize));
        } else {
            AppendLog(L"[ERREUR] Analyse PE impossible: " + err);
        }
    } else {
        // Récupération automatique via les modules du processus
        uint64_t base = 0; uint32_t size = 0;
        if (GetProcessImageBase(hProcess, base, size)) {
            g_imageBase = base;
            g_imageSize = size;
            AppendLog(L"[INFO] Processus sélectionné PID=" + Dec(pid) + L", ImageBase=0x" + Hex64(base, 16) + L", Taille=" + Dec(size));
        } else {
            AppendLog(L"[INFO] Aucun PE chargé et impossible de déterminer automatiquement l'image base du processus.");
            g_imageBase = 0;
            g_imageSize = 0;
        }
    }
    SetStatus(L"Processus sélectionné - PID " + Dec(pid));
}

// --------------------------- Gestion de l'interface ---------------------------
static void LayoutControls(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int margin = 10;
    int y = 10;
    int btnH = 30;
    int btnW = 120;

    MoveWindow(g_hIconBox, margin, y, 32, 32, TRUE);
    MoveWindow(g_hHeader, margin + 42, y, w - margin * 2 - 42, 32, TRUE);
    y += 42;

    int x = margin;

    struct ButtonLayout { HWND h; int w; } ctrls[] = {
        {GetDlgItem(hwnd, IDC_BTN_OPEN), 98},
        {GetDlgItem(hwnd, IDC_BTN_UNPACK), 108},
        {GetDlgItem(hwnd, IDC_BTN_ANALYZE), 96},
        {GetDlgItem(hwnd, IDC_BTN_DECOMPILE), 126},
        {GetDlgItem(hwnd, IDC_BTN_STRINGS), 110},
        {GetDlgItem(hwnd, IDC_BTN_BRUTEFORCE), 96},
        {GetDlgItem(hwnd, IDC_BTN_XDR), 70},
        {GetDlgItem(hwnd, IDC_BTN_CONVERT), 105},
        {GetDlgItem(hwnd, IDC_BTN_RECOMPILE), 96},
        {GetDlgItem(hwnd, IDC_BTN_DECRYPTOR), 92},
        {GetDlgItem(hwnd, IDC_BTN_RUN), 100},
        {GetDlgItem(hwnd, IDC_BTN_SELECT_PROC), 140},
        {GetDlgItem(hwnd, IDC_BTN_DUMP), 115},
        {GetDlgItem(hwnd, IDC_BTN_LOAD_DUMP), 110},
        {GetDlgItem(hwnd, IDC_BTN_DUMPLIVE), 90},
        {GetDlgItem(hwnd, IDC_BTN_EXPORT), 112},
        {GetDlgItem(hwnd, IDC_BTN_CLEAR), 86},
        {GetDlgItem(hwnd, IDC_BTN_QUIT), 70}
    };

    for (const auto& c : ctrls) { if (!c.h) continue; if (x + c.w > w - margin) { x = margin; y += btnH + 7; } MoveWindow(c.h, x, y, c.w, btnH, TRUE); x += c.w + 7; }
    y += btnH + 10;

    int statusH = 24;
    MoveWindow(g_hLog, margin, y, w - margin * 2, h - y - statusH - margin * 2, TRUE);
    MoveWindow(g_hStatus, margin, h - statusH - margin, w - margin * 2, statusH, TRUE);
}

static HFONT CreateUiFont(int pts, bool bold = false) {
    HDC hdc = GetDC(nullptr);
    int height = -MulDiv(pts, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, hdc);
    return CreateFontW(height, 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT font = nullptr;
    static HFONT fontHeader = nullptr;

    switch (msg) {
    case WM_CREATE: {
        font = CreateUiFont(9, false);
        fontHeader = CreateUiFont(14, true);
        HICON iconBig = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
        HICON iconSmall = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)iconBig);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)iconSmall);

        HMENU menuBar = CreateMenu();
        HMENU menuFile = CreatePopupMenu();
        AppendMenuW(menuFile, MF_STRING, IDM_FILE_OPEN_PE, L"Ouvrir PE...");
        AppendMenuW(menuFile, MF_STRING, IDM_FILE_OPEN_DECOMP_C, L"Ouvrir/éditer fichier décompilé...");
        AppendMenuW(menuFile, MF_STRING, IDM_FILE_OPEN_OUTPUT_DIR, L"Ouvrir dossier de sortie");
        AppendMenuW(menuFile, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menuFile, MF_STRING, IDM_FILE_EXPORT_REPORT, L"Exporter rapport...");
        AppendMenuW(menuFile, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menuFile, MF_STRING, IDM_FILE_EXIT, L"Quitter");
        AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)menuFile, L"Fichier");

        HMENU menuTools = CreatePopupMenu();
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_DECOMPILE, L"Décompilation standard");
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_BRUTEFORCE, L"Décompilation bruteforce");
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_CONVERT_DIR, L"Convert C/C++...");
        AppendMenuW(menuTools, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_RECOMPILE_DIR, L"Recompiler un dossier...");
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_DECRYPTOR, L"Décryptor statique...");
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_GEN_SCRIPT, L"Générer script x64dbg");
        AppendMenuW(menuTools, MF_STRING, IDM_TOOLS_XDR, L"XDR-Protect (privé)");
        AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)menuTools, L"Outils");
        SetMenu(hwnd, menuBar);

        HMENU menuHelp = CreatePopupMenu();
        AppendMenuW(menuHelp, MF_STRING, IDM_HELP_ETHICS, L"À propos / Éthique");
        AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)menuHelp, L"Infos");

        g_hIconBox = CreateWindowW(L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON, 0, 0, 32, 32, hwnd, (HMENU)IDC_ICONBOX, g_hInst, nullptr);
        SendMessageW(g_hIconBox, STM_SETICON, (WPARAM)iconBig, 0);

        g_hHeader = CreateWindowW(L"STATIC", L"ZennComp - AVHIRAL PE Static Decompiler Workbench", WS_CHILD | WS_VISIBLE,
                                  0, 0, 100, 30, hwnd, (HMENU)IDC_HEADER, g_hInst, nullptr);
        SendMessageW(g_hHeader, WM_SETFONT, (WPARAM)fontHeader, TRUE);

        auto btn = [&](int id, const wchar_t* text) {
            HWND b = CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   0, 0, 100, 30, hwnd, (HMENU)(INT_PTR)id, g_hInst, nullptr);
            SendMessageW(b, WM_SETFONT, (WPARAM)font, TRUE);
        };
        btn(IDC_BTN_OPEN, L"Ouvrir EXE");
        btn(IDC_BTN_UNPACK, L"Décompresser UPX");
        btn(IDC_BTN_ANALYZE, L"Analyser PE");
        btn(IDC_BTN_DECOMPILE, L"Décompilation");
        btn(IDC_BTN_STRINGS, L"Extraire chaines");
        btn(IDC_BTN_BRUTEFORCE, L"Bruteforce");
        btn(IDC_BTN_RUN, L"Lancer EXE");
        btn(IDC_BTN_SELECT_PROC, L"Sélectionner processus");
        btn(IDC_BTN_DUMP, L"Dumper mémoire");
        btn(IDC_BTN_LOAD_DUMP, L"Charger dump");
        btn(IDC_BTN_DUMPLIVE, L"DumpLive");
        btn(IDC_BTN_CONVERT, L"Convert C/C++");
        btn(IDC_BTN_RECOMPILE, L"Recompiler");
        btn(IDC_BTN_DECRYPTOR, L"Décryptor");
        btn(IDC_BTN_EXPORT, L"Exporter rapport");
        btn(IDC_BTN_CLEAR, L"Effacer logs");
        btn(IDC_BTN_QUIT, L"Quitter");

        g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                                 WS_VSCROLL | WS_HSCROLL | ES_READONLY,
                                 0, 0, 100, 100, hwnd, (HMENU)IDC_LOG, g_hInst, nullptr);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"), TRUE);

        g_hStatus = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"Pret - charge un EXE/DLL/SYS pour analyse statique.",
                                    WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 100, 24, hwnd, (HMENU)IDC_STATUS, g_hInst, nullptr);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)font, TRUE);

        AppendLog(L"ZennComp V9 demarre.");
        AppendLog(L"Mode securise: analyse statique uniquement, aucune execution du binaire cible.");
        LayoutControls(hwnd);
        return 0;
    }
    case WM_SIZE:
        LayoutControls(hwnd);
        return 0;
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_BTN_OPEN: OpenTargetFile(); return 0;
        case IDC_BTN_UNPACK: DoUnpack(); return 0;
        case IDC_BTN_ANALYZE: DoAnalyze(false, false, false); return 0;
        case IDC_BTN_DECOMPILE: DoAnalyze(true, true, true); return 0;
        case IDC_BTN_STRINGS: DoAnalyze(true, false, false); return 0;
        case IDM_TOOLS_GEN_SCRIPT: {
            std::wstring dir, err;
            if (!GetOutputDirChecked(dir, err)) {
               MessageBoxW(g_hWnd, err.c_str(), L"Erreur", MB_ICONERROR);
                return 0;
            }
            if (GenerateX64dbgScript(dir))
                AppendLog(L"[OK] Script x64dbg généré dans " + dir);
            else
                AppendLog(L"[ERREUR] Échec de la génération du script.");
            return 0;
        }
        case IDC_BTN_BRUTEFORCE: DoBruteforce(); return 0;
        case IDC_BTN_XDR:
        case IDM_TOOLS_XDR:
            DoXdrBruteforce();
            return 0;
        case IDC_BTN_SELECT_PROC:
            DoSelectProcess();
            return 0;
        case IDC_BTN_RUN:
            DoRunTarget();
            return 0;
        case IDC_BTN_DUMP:
            DoDumpMemory();
            return 0;
        case IDC_BTN_LOAD_DUMP:
            DoLoadDump();
            return 0;
        case IDC_BTN_DUMPLIVE:
            DoDumpLive();
            return 0;
        case IDM_HELP_ETHICS:
            ShowEthicsDialog(hwnd);
            return 0;
        case IDC_BTN_CONVERT: DoConvertCCpp(); return 0;
        case IDC_BTN_RECOMPILE: DoRecompile(); return 0;
        case IDC_BTN_DECRYPTOR: DoDecryptorAnalysis(); return 0;
        case IDC_BTN_EXPORT: ExportReport(); return 0;
        case IDC_BTN_CLEAR: ClearLog(); SetStatus(L"Logs effaces."); return 0;
        case IDC_BTN_QUIT: DestroyWindow(hwnd); return 0;
        case IDM_FILE_OPEN_PE: OpenTargetFile(); return 0;
        case IDM_FILE_OPEN_DECOMP_C: ChooseAndOpenDecompiledFile(); return 0;
        case IDM_FILE_OPEN_OUTPUT_DIR: OpenOutputDirectory(); return 0;
        case IDM_FILE_EXPORT_REPORT: ExportReport(); return 0;
        case IDM_FILE_EXIT: DestroyWindow(hwnd); return 0;
        case IDM_TOOLS_DECOMPILE: DoAnalyze(true, true, true); return 0;
        case IDM_TOOLS_BRUTEFORCE: DoBruteforce(); return 0;
        case IDM_TOOLS_CONVERT_DIR: DoConvertCCpp(); return 0;
        case IDM_TOOLS_RECOMPILE_DIR: DoRecompile(); return 0;
        case IDM_TOOLS_DECRYPTOR: DoDecryptorAnalysis(); return 0;
        default: break;
        }
        break;
    }
        case WM_DESTROY:
        // Arrêt propre du thread DumpLive s'il est actif
        if (g_dumpLiveRunning) {
            g_dumpLiveRunning = false;               // signal d'arrêt
            if (g_hDumpThread) {
                // Attendre jusqu'à 5 secondes que le thread se termine
                WaitForSingleObject(g_hDumpThread, 5000);
                CloseHandle(g_hDumpThread);
                g_hDumpThread = nullptr;
            }
        }
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Installer le traducteur SEH -> C++
    _set_se_translator(SeTranslator);

    g_hInst = hInstance;
    g_hRichEdit = LoadLibraryW(L"Riched20.dll");
    if (!g_hRichEdit) g_hRichEdit = LoadLibraryW(L"Msftedit.dll");

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    const wchar_t* cls = L"ZennCompMainWindow";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = hInstance;
    wc.lpfnWndProc = WndProc;
    wc.lpszClassName = cls;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ZENNCOMP));
    wc.hIconSm = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_ZENNCOMP), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"RegisterClassExW a echoue.", L"ZennComp", MB_ICONERROR);
        return 1;
    }

    g_hWnd = CreateWindowExW(0, cls, L"ZennComp - AVHIRAL", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 1100, 760,
                             nullptr, nullptr, hInstance, nullptr);
    if (!g_hWnd) {
        MessageBoxW(nullptr, L"CreateWindowExW a echoue.", L"ZennComp", MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}