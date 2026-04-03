#include "elf_reader.h"
#include <android/log.h>
#include <dlfcn.h>
#include <iomanip>
#include <sstream>
#include <vector>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "elf_reader", __VA_ARGS__)

using namespace ELFIO;

void ElfReader::Analyze(const char* soname) {
    void* handle = dlopen(soname, RTLD_NOW);
    if (!handle) {
        LOG("无法 dlopen: %s", soname);
        return;
    }

    // 利用符号定位磁盘路径
    void* sym = dlsym(handle, "TestSample");
    Dl_info info;
    if (dladdr(sym, &info) && info.dli_fname) {
        LOG("开始深度解析 ELF: %s", info.dli_fname);
        ElfReader reader(info.dli_fname);
        if (reader.Load()) {
            reader.DumpAll();
        }
    }
    dlclose(handle);
}

ElfReader::ElfReader(const char* path) : path_(path) {}

ElfReader::~ElfReader() {}

bool ElfReader::Load() {
    loaded_ = reader_.load(path_);
    if (!loaded_) LOG("ELFIO 加载失败: %s", path_.c_str());
    return loaded_;
}

void ElfReader::DumpAll() {
    DumpElfHeader();
    DumpLoadSegments();
    DumpDynamicSymbols();
    DumpStaticSymbols();
    DumpDependencies();
    DumpRelocations();
    DumpJumpTables();
    DumpSectionTable();
    DumpSpecialSections();
}

// 1. ELF Header
void ElfReader::DumpElfHeader() {
    LOG("[1. ELF Header 基本信息]");
    LOG("类型: %d, 架构: %d, 入口点: 0x%lx",
         reader_.get_type(), reader_.get_machine(), reader_.get_entry());
}

// 2. PT_LOAD
void ElfReader::DumpLoadSegments() {
    LOG("[2. 段加载信息 PT_LOAD]");
    for (int i = 0; i < reader_.segments.size(); ++i) {
        const segment* seg = reader_.segments[i];
        if (seg->get_type() == PT_LOAD) {
            std::string p;
            p += (seg->get_flags() & PF_R) ? "R" : "-";
            p += (seg->get_flags() & PF_W) ? "W" : "-";
            p += (seg->get_flags() & PF_X) ? "X" : "-";
            LOG("虚拟地址: 0x%lx, 内存大小: %lu, 权限: [%s]",
                 seg->get_virtual_address(), seg->get_memory_size(), p.c_str());
        }
    }
}

// 3. .dynsym
void ElfReader::DumpDynamicSymbols() {
    LOG("[3. 动态符号表 .dynsym]");
    section* sec = FindSection(".dynsym");
    if (!sec) return;

    symbol_section_accessor symbols(reader_, sec);
    for (int i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name;
        Elf64_Addr value;
        Elf_Xword size;
        unsigned char bind, type, other; unsigned short shndx;
        symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
        if (!name.empty() && type == STT_FUNC) {
            LOG("%-30s 地址:0x%08lx, 大小:%lu", name.c_str(), value, size);
        }
    }
}

// 4. .symtab
void ElfReader::DumpStaticSymbols() {
    section* sec = FindSection(".symtab");
    if (!sec) {
        LOG("[4. .symtab] 未发现或已被 strip");
        return;
    }
    LOG("[4. 静态符号表 .symtab]");
    symbol_section_accessor symbols(reader_, sec);
    for (int i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name; Elf64_Addr value; Elf_Xword size;
        unsigned char bind, type, other; unsigned short shndx;
        symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
        if (!name.empty()) LOG("%-30s 地址:0x%08lx", name.c_str(), value);
    }
}

// 5. .dynamic (DT_NEEDED)
void ElfReader::DumpDependencies() {
    LOG("[5. 依赖库列表 .dynamic]");
    section* sec = FindSection(".dynamic");
    if (!sec) return;

    dynamic_section_accessor dynamic(reader_, sec);
    for (int i = 0; i < dynamic.get_entries_num(); ++i) {
        Elf_Xword tag, value; std::string str;
        dynamic.get_entry(i, tag, value, str);
        if (tag == DT_NEEDED) LOG("%s", str.c_str());
    }
}

// 6. 重定位表 (红色重点)
void ElfReader::DumpRelocations() {
    LOG("[6. 重定位表 .rela.dyn / .rela.plt]");
    std::vector<std::string> relas = {".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt"};
    for (auto& name : relas) {
        section* sec = FindSection(name);
        if (!sec) continue;
        LOG("节名: %s", name.c_str());
        relocation_section_accessor res(reader_, sec);
        for (int i = 0; i < res.get_entries_num(); ++i) {
            Elf64_Addr offset, sym_val; std::string sym_name;
            Elf_Word type; Elf_Sxword addend, calc;
            res.get_entry(i, offset, sym_val, sym_name, type, addend, calc);
            LOG("偏移:0x%08lx, 类型:0x%02x, 关联符号:%s", offset, type, sym_name.c_str());
        }
    }
}

// 7. 跳转表 (红色重点)
void ElfReader::DumpJumpTables() {
    LOG("[7. 跳转表 .plt / .got.plt]");
    std::vector<std::string> jmps = {".plt", ".got", ".got.plt"};
    for (auto& name : jmps) {
        section* sec = FindSection(name);
        if (!sec) continue;
        LOG("%s (地址:0x%lx, 大小:%lu)", name.c_str(), sec->get_address(), sec->get_size());
        DumpHex(sec->get_data(), sec->get_size() > 32 ? 32 : sec->get_size());
    }
}

// 8. 节表完整列表
void ElfReader::DumpSectionTable() {
    LOG("[8. 节表完整列表名称/地址/大小/权限]");
    for (int i = 0; i < reader_.sections.size(); ++i) {
        const section* sec = reader_.sections[i];
        LOG("[%2d] %-18s 地址:0x%08lx, 大小:%lu",
             i, sec->get_name().c_str(), sec->get_address(), sec->get_size());
    }
}

// 9. 特殊节
void ElfReader::DumpSpecialSections() {
    LOG("[9. 异常/调试/只读内容]");
    // .eh_frame
    section* eh = FindSection(".eh_frame");
    if (eh) LOG(".eh_frame: 异常回溯信息, 大小:%lu", eh->get_size());

    // .debug_*
    for (int i = 0; i < reader_.sections.size(); ++i) {
        std::string name = reader_.sections[i]->get_name();
        if (name.find(".debug") == 0) LOG("DWARF调试信息: %s, 大小:%lu", name.c_str(), reader_.sections[i]->get_size());
    }

    // .rodata
    section* ro = FindSection(".rodata");
    if (ro) {
        LOG(".rodata 只读数据内容预览:");
        DumpHex(ro->get_data(), ro->get_size() > 64 ? 64 : ro->get_size());
    }
}

void ElfReader::DumpHex(const char* data, size_t size, const std::string& prefix) {
    if (!data) return;
    std::stringstream ss;
    for (size_t i = 0; i < size; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)data[i] << " ";
        if ((i + 1) % 16 == 0 && i != size - 1) ss << "\n" << prefix;
    }
    LOG("%s%s", prefix.c_str(), ss.str().c_str());
}

section* ElfReader::FindSection(const std::string& name) {
    for (int i = 0; i < reader_.sections.size(); ++i) {
        if (reader_.sections[i]->get_name() == name) return reader_.sections[i];
    }
    return nullptr;
}