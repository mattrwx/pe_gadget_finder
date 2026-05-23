#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct pattern_byte {
    uint8_t value;
    bool    wildcard;
};

std::vector<pattern_byte> parse_pattern(const std::string& raw) {
    std::vector<pattern_byte> out;
    std::istringstream ss(raw);
    std::string tok;

    while (ss >> tok) {
        pattern_byte pb{};
        if (tok == "?" || tok == "??") {
            pb.wildcard = true;
        } else {
            try {
                pb.value    = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                pb.wildcard = false;
            } catch (...) {
                std::cerr << "[!] Invalid token in pattern: \"" << tok << "\"\n";
                return {};
            }
        }
        out.push_back(pb);
    }
    return out;
}

std::vector<size_t> find_pattern(const uint8_t*                   data,
                                  size_t                            data_size,
                                  const std::vector<pattern_byte>& pat) {
    std::vector<size_t> hits;
    if (pat.empty() || data_size < pat.size()) return hits;

    const size_t last = data_size - pat.size();
    for (size_t i = 0; i <= last; ++i) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (!pat[j].wildcard && data[i + j] != pat[j].value) {
                ok = false;
                break;
            }
        }
        if (ok) hits.push_back(i);
    }
    return hits;
}

struct match_result {
    uintptr_t   rva;
    std::string section;
    std::string file;
    std::string instruction;
};

struct mapped_file {
    const uint8_t* base      = nullptr;
    size_t         file_size = 0;
    HANDLE         h_file    = INVALID_HANDLE_VALUE;
    HANDLE         h_map     = nullptr;

    bool open(const fs::path& path) {
        h_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_file == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER li{};
        GetFileSizeEx(h_file, &li);
        if (li.QuadPart == 0) { close(); return false; }
        file_size = static_cast<size_t>(li.QuadPart);

        h_map = CreateFileMappingW(h_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!h_map) { close(); return false; }

        base = static_cast<const uint8_t*>(MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0));
        if (!base) { close(); return false; }
        return true;
    }

    void close() {
        if (base)  { UnmapViewOfFile(base); base = nullptr; }
        if (h_map) { CloseHandle(h_map);    h_map = nullptr; }
        if (h_file != INVALID_HANDLE_VALUE) {
            CloseHandle(h_file);
            h_file = INVALID_HANDLE_VALUE;
        }
    }

    ~mapped_file() { close(); }
};

static std::string get_section_name(const IMAGE_SECTION_HEADER& sec) {
    char buf[9]{};
    std::memcpy(buf, sec.Name, 8);
    return std::string(buf);
}

static std::string disassemble_at(const uint8_t*                   data,
                                   size_t                           max_len,
                                   ZydisDecoder&                    decoder,
                                   ZydisFormatter&                  formatter,
                                   ZyanU64                          runtime_addr) {
    ZydisDecodedInstruction instr{};
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, max_len,
                                              &instr, operands)))
        return "<disasm failed>";

    char buf[256]{};
    if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
            &formatter, &instr, operands,
            instr.operand_count_visible,
            buf, sizeof(buf),
            runtime_addr, nullptr)))
        return "<format failed>";

    return std::string(buf);
}

std::vector<match_result> scan_pe(const fs::path&                  path,
                                   const std::vector<pattern_byte>& pat,
                                   bool                             all_sections) {
    std::vector<match_result> results;

    mapped_file mf;
    if (!mf.open(path)) return results;

    const uint8_t* base = mf.base;
    size_t         sz   = mf.file_size;

    if (sz < sizeof(IMAGE_DOS_HEADER)) return results;
    auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return results;

    LONG pe_off = dos_hdr->e_lfanew;
    if (pe_off < 0 || static_cast<size_t>(pe_off) + sizeof(IMAGE_NT_HEADERS32) > sz)
        return results;

    auto* nt_sig = reinterpret_cast<const DWORD*>(base + pe_off);
    if (*nt_sig != IMAGE_NT_SIGNATURE) return results;

    auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        base + pe_off + sizeof(DWORD));

    WORD num_sections  = file_hdr->NumberOfSections;
    WORD opt_header_sz = file_hdr->SizeOfOptionalHeader;

    ZydisMachineMode machine_mode;
    ZydisStackWidth  stack_width;

    if (file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64 ||
        file_hdr->Machine == IMAGE_FILE_MACHINE_IA64) {
        machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        stack_width  = ZYDIS_STACK_WIDTH_64;
    } else {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
        stack_width  = ZYDIS_STACK_WIDTH_32;
    }

    ZydisDecoder   decoder{};
    ZydisFormatter formatter{};
    ZydisDecoderInit(&decoder, machine_mode, stack_width);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    size_t sec_off = static_cast<size_t>(pe_off)
                     + sizeof(DWORD)
                     + sizeof(IMAGE_FILE_HEADER)
                     + opt_header_sz;

    if (sec_off + num_sections * sizeof(IMAGE_SECTION_HEADER) > sz)
        return results;

    auto* section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sec_off);

    const std::string file_name = path.filename().string();

    for (WORD i = 0; i < num_sections; ++i) {
        const IMAGE_SECTION_HEADER& sec = section_table[i];

        bool is_exec = (sec.Characteristics & IMAGE_SCN_CNT_CODE) != 0
                    || (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (!all_sections && !is_exec) continue;

        DWORD raw_off   = sec.PointerToRawData;
        DWORD raw_size  = sec.SizeOfRawData;
        DWORD virt_addr = sec.VirtualAddress;

        if (raw_size == 0 || raw_off == 0) continue;
        if (static_cast<size_t>(raw_off) + raw_size > sz) continue;

        const uint8_t* sec_data = base + raw_off;
        auto hits = find_pattern(sec_data, raw_size, pat);

        for (size_t off : hits) {
            match_result m;
            m.rva         = static_cast<uintptr_t>(virt_addr + off);
            m.section     = get_section_name(sec);
            m.file        = file_name;
            m.instruction = disassemble_at(sec_data + off,
                                            raw_size - off,
                                            decoder,
                                            formatter,
                                            static_cast<ZyanU64>(virt_addr + off));
            results.push_back(std::move(m));
        }
    }

    return results;
}

// Case-insensitive prefix match: does `instr` start with `filter`?
// Whitespace in the filter is normalised so "mov  cr3" == "mov cr3".
static std::string normalise_instr(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool last_space = false;
    for (unsigned char c : s) {
        if (std::isspace(c)) {
            if (!last_space && !out.empty()) { out += ' '; last_space = true; }
        } else {
            out += (char)std::tolower(c);
            last_space = false;
        }
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

static bool instr_matches_filter(const std::string& instr,
                                  const std::string& norm_filter) {
    if (norm_filter.empty()) return false;
    std::string norm_instr = normalise_instr(instr);
    if (norm_instr.size() < norm_filter.size()) return false;
    // prefix match
    if (norm_instr.substr(0, norm_filter.size()) != norm_filter) return false;
    // make sure the match lands on a token boundary (end of string, space,
    // or comma) so "mov cr3" doesn't match "mov cr30"
    if (norm_instr.size() > norm_filter.size()) {
        char next = norm_instr[norm_filter.size()];
        if (next != ' ' && next != ',' && next != '\t') return false;
    }
    return true;
}

std::optional<std::string> get_arg(const std::string& arg,
                                    const std::string& key) {
    std::string prefix = "-" + key + "=";
    if (arg.size() < prefix.size()) return std::nullopt;
    for (size_t i = 0; i < prefix.size(); ++i)
        if (std::tolower((unsigned char)arg[i]) != std::tolower((unsigned char)prefix[i]))
            return std::nullopt;

    std::string val = arg.substr(prefix.size());
    if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
        val = val.substr(1, val.size() - 2);
    return val;
}

void print_usage(const char* prog) {
    std::cout
        << "\nUsage:\n"
        << "  " << prog
        << " -dir=\"<path>\" -pattern=\"<IDA pattern>\" [-bin=\"<output>\"] [-extension=\"<exts>\"] [-instruction=\"<text>\"] [-ALLFILE]\n\n"
        << "Options:\n"
        << "  -dir=<path>          Directory to scan (recursive)\n"
        << "  -pattern=<pat>       IDA-style hex pattern  e.g. \"0F 22 ? 05\"\n"
        << "                       Use ? or ?? as single-byte wildcards\n"
        << "  -bin=<file>          Output file (default: matches.txt)\n"
        << "                       .txt is appended if no extension is given\n"
        << "  -extension=<exts>    Space-separated list of extensions to scan\n"
        << "                       e.g. \"sys dll\" or \".sys .dll\"\n"
        << "                       Default: exe dll sys ocx scr drv efi mui\n"
        << "  -instruction=<text>  Prefix filter on disassembled instruction\n"
        << "                       Matching rows are promoted to the top of the output\n"
        << "                       e.g. \"mov cr3, rcx\" or \"mov cr3\" (partial ok)\n"
        << "  -ALLFILE             Scan ALL sections, not just executable ones\n\n"
        << "Supported PE extensions (default): .exe .dll .sys .ocx .scr .drv .efi .mui\n\n"
        << "Output format:\n"
        << "  RVA                | Section    | File                | Instruction\n\n";
}

static std::string pad_right(std::string s, size_t width) {
    if (s.size() < width) s.append(width - s.size(), ' ');
    return s;
}

static std::string rva_str(uintptr_t rva) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase
        << std::setfill('0') << std::setw(16) << rva;
    return oss.str();
}

static void write_row(std::ofstream&     out,
                       const std::string& col_rva,
                       const std::string& col_sec,
                       const std::string& col_file,
                       const std::string& col_instr,
                       size_t             w_rva,
                       size_t             w_sec,
                       size_t             w_file) {
    out << pad_right(col_rva,   w_rva)   << " | "
        << pad_right(col_sec,   w_sec)   << " | "
        << pad_right(col_file,  w_file)  << " | "
        << col_instr << "\n";
}

static void write_separator(std::ofstream& out,
                              size_t w_rva, size_t w_sec,
                              size_t w_file, size_t w_instr) {
    auto dashes = [](size_t n) { return std::string(n, '-'); };
    out << dashes(w_rva)   << "-+-"
        << dashes(w_sec)   << "-+-"
        << dashes(w_file)  << "-+-"
        << dashes(w_instr) << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "pegadgetfinder  -  PE pattern scanner\n"
              << "======================================\n";

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string dir_arg, pattern_arg, bin_file, ext_arg, instr_filter;
    bool all_file = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        std::string a_upper = a;
        std::transform(a_upper.begin(), a_upper.end(), a_upper.begin(),
                        [](unsigned char c){ return (char)std::toupper(c); });
        if (a_upper == "-ALLFILE") { all_file = true; continue; }

        if (auto v = get_arg(a, "dir"))         { dir_arg      = *v; continue; }
        if (auto v = get_arg(a, "pattern"))     { pattern_arg  = *v; continue; }
        if (auto v = get_arg(a, "bin"))         { bin_file     = *v; continue; }
        if (auto v = get_arg(a, "extension"))   { ext_arg      = *v; continue; }
        if (auto v = get_arg(a, "instruction")) { instr_filter = *v; continue; }

        std::cerr << "[!] Unknown argument: " << a << "\n";
    }

    if (dir_arg.empty()) {
        std::cerr << "[!] -dir is required.\n";
        print_usage(argv[0]);
        return 1;
    }
    if (pattern_arg.empty()) {
        std::cerr << "[!] -pattern is required.\n";
        print_usage(argv[0]);
        return 1;
    }

    if (bin_file.empty()) bin_file = "matches";
    if (fs::path(bin_file).extension().empty()) bin_file += ".txt";

    // Build extension list from -extension= arg, or fall back to defaults
    std::vector<std::string> pe_exts;
    if (!ext_arg.empty()) {
        std::istringstream ess(ext_arg);
        std::string tok;
        while (ess >> tok) {
            std::transform(tok.begin(), tok.end(), tok.begin(),
                           [](unsigned char c){ return (char)std::tolower(c); });
            if (tok.front() != '.') tok = '.' + tok;
            pe_exts.push_back(tok);
        }
        if (pe_exts.empty()) {
            std::cerr << "[!] -extension= was given but parsed to zero entries. Aborting.\n";
            return 1;
        }
    } else {
        pe_exts = { ".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".efi", ".mui" };
    }

    auto pat_bytes = parse_pattern(pattern_arg);
    if (pat_bytes.empty()) {
        std::cerr << "[!] Pattern parsed to zero bytes. Aborting.\n";
        return 1;
    }

    fs::path dir_path(dir_arg);
    std::error_code ec;
    if (!fs::exists(dir_path, ec) || !fs::is_directory(dir_path, ec)) {
        std::cerr << "[!] Directory not found or inaccessible: " << dir_arg << "\n";
        return 1;
    }

    std::cout << "[*] Directory : " << dir_arg     << "\n"
              << "[*] Pattern   : " << pattern_arg << "  ("
                                    << pat_bytes.size() << " byte(s))\n"
              << "[*] Output    : " << bin_file    << "\n"
              << "[*] Scope     : "
                  << (all_file ? "all sections" : "executable sections only") << "\n"
              << "[*] Extensions:";
    for (const auto& e : pe_exts) std::cout << " " << e;
    std::cout << "\n\n";

    std::vector<match_result> all_results;
    size_t file_count = 0;

    const auto dir_opts = fs::directory_options::skip_permission_denied;
    for (const auto& entry : fs::recursive_directory_iterator(dir_path, dir_opts, ec)) {
        if (!entry.is_regular_file(ec)) continue;

        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
                        [](unsigned char c){ return (char)std::tolower(c); });

        if (std::find(pe_exts.begin(), pe_exts.end(), ext) == pe_exts.end()) continue;

        ++file_count;

        std::cout << "\r[~] Scanning (" << file_count << ")  "
                  << entry.path().filename().string()
                  << "                    " << std::flush;

        auto hits = scan_pe(entry.path(), pat_bytes, all_file);
        for (auto& m : hits)
            all_results.push_back(std::move(m));
    }

    std::cout << "\n\n";

    // --- NEW INSTRUCTION FILTERING LOGIC ---
    // If a filter was provided, move matching items to the top of the vector
    // while preserving the original relative order for both groups
    if (!instr_filter.empty()) {
        std::string norm_filter = normalise_instr(instr_filter);
        std::stable_partition(all_results.begin(), all_results.end(),
            [&norm_filter](const match_result& m) {
                return instr_matches_filter(m.instruction, norm_filter);
            });
    }
    // ---------------------------------------

    const std::string hdr_rva   = "RVA";
    const std::string hdr_sec   = "Section";
    const std::string hdr_file  = "File";
    const std::string hdr_instr = "Instruction";

    size_t w_rva   = hdr_rva.size();
    size_t w_sec   = hdr_sec.size();
    size_t w_file  = hdr_file.size();
    size_t w_instr = hdr_instr.size();

    for (const auto& m : all_results) {
        w_rva   = std::max(w_rva,   rva_str(m.rva).size());
        w_sec   = std::max(w_sec,   m.section.size());
        w_file  = std::max(w_file,  m.file.size());
        w_instr = std::max(w_instr, m.instruction.size());
    }

    std::ofstream out_file(bin_file, std::ios::trunc);
    if (!out_file) {
        std::cerr << "[!] Cannot open output file: " << bin_file << "\n";
        return 1;
    }

    out_file << "# pegadgetfinder - pattern scan results\n"
             << "# Pattern  : " << pattern_arg << "\n"
             << "# Directory: " << dir_arg     << "\n"
             << "# Scope    : " << (all_file ? "all sections" : "executable sections only") << "\n"
             << "# Extensions:";
    for (const auto& e : pe_exts) out_file << " " << e;
    out_file << "\n";
    if (!instr_filter.empty()) {
        out_file << "# Filter   : " << instr_filter << " (matching items promoted to top)\n";
    }
    out_file << "#\n";

    write_row(out_file, hdr_rva, hdr_sec, hdr_file, hdr_instr,
              w_rva, w_sec, w_file);
    write_separator(out_file, w_rva, w_sec, w_file, w_instr);

    for (const auto& m : all_results) {
        write_row(out_file,
                  rva_str(m.rva), m.section, m.file, m.instruction,
                  w_rva, w_sec, w_file);
    }

    size_t match_count = all_results.size();

    std::cout << "[+] Scanned  : " << file_count  << " PE file(s)\n"
              << "[+] Matches  : " << match_count << "\n"
              << "[+] Output   : " << bin_file << "\n";

    if (match_count == 0)
        std::cout << "[i] No matches found. Try -ALLFILE to include non-executable sections.\n";

    return 0;
}