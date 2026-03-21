#include "elf_reader.h"
#include <android/log.h>
#include <dlfcn.h>
#include <iomanip>
#include <sstream>
#include <vector>

#define TAG "ELF_READER"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

using namespace ELFIO;

void ElfReader::Analyze(const char* soname) {
    void* handle = dlopen(soname, RTLD_NOW);
    if (!handle) {
        LOGI("!! 无法 dlopen: %s", soname);
        return;
    }

    // 利用符号定位磁盘路径
    void* sym = dlsym(handle, "test_sample");
    Dl_info info;
    if (dladdr(sym, &info) && info.dli_fname) {
        LOGI("======================================================");
        LOGI(">> 开始深度解析 ELF: %s", info.dli_fname);
        ElfReader reader(info.dli_fname);
        if (reader.load()) {
            reader.dumpAll();
        }
        LOGI("======================================================");
    }
    dlclose(handle);
}

ElfReader::ElfReader(const char* path) : path_(path) {}

ElfReader::~ElfReader() {}

bool ElfReader::load() {
    loaded_ = reader_.load(path_);
    if (!loaded_) LOGI("!! ELFIO 加载失败: %s", path_.c_str());
    return loaded_;
}

void ElfReader::dumpAll() {
    dumpElfHeader();
    dumpLoadSegments();
    dumpDynamicSymbols();
    dumpStaticSymbols();
    dumpDependencies();
    dumpRelocations();
    dumpJumpTables();
    dumpSectionTable();
    dumpSpecialSections();
}

// 1. ELF Header
void ElfReader::dumpElfHeader() {
    LOGI("[1. ELF Header 基本信息]");
    LOGI("   类型: %d, 架构: %d, 入口点: 0x%llx",
         reader_.get_type(), reader_.get_machine(), reader_.get_entry());
}

// 2. PT_LOAD
void ElfReader::dumpLoadSegments() {
    LOGI("[2. 段加载信息 PT_LOAD]");
    for (int i = 0; i < reader_.segments.size(); ++i) {
        const segment* seg = reader_.segments[i];
        if (seg->get_type() == PT_LOAD) {
            std::string p = "";
            p += (seg->get_flags() & PF_R) ? "R" : "-";
            p += (seg->get_flags() & PF_W) ? "W" : "-";
            p += (seg->get_flags() & PF_X) ? "X" : "-";
            LOGI("   虚拟地址: 0x%llx, 内存大小: 0x%llx, 权限: [%s]",
                 seg->get_virtual_address(), seg->get_memory_size(), p.c_str());
        }
    }
}

// 3. .dynsym
void ElfReader::dumpDynamicSymbols() {
    LOGI("[3. 动态符号表 .dynsym]");
    section* sec = findSection(".dynsym");
    if (!sec) return;

    symbol_section_accessor symbols(reader_, sec);
    for (int i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name; Elf64_Addr value; Elf_Xword size;
        unsigned char bind, type, other; unsigned short shndx;
        symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
        if (!name.empty() && type == STT_FUNC) {
            LOGI("   %-30s 地址:0x%08llx, 大小:%llu", name.c_str(), value, size);
        }
    }
}

// 4. .symtab
void ElfReader::dumpStaticSymbols() {
    section* sec = findSection(".symtab");
    if (!sec) {
        LOGI("[4. .symtab] 未发现或已被 strip");
        return;
    }
    LOGI("[4. 静态符号表 .symtab]");
    symbol_section_accessor symbols(reader_, sec);
    for (int i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name; Elf64_Addr value; Elf_Xword size;
        unsigned char bind, type, other; unsigned short shndx;
        symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
        if (!name.empty()) LOGI("   %-30s 地址:0x%08llx", name.c_str(), value);
    }
}

// 5. .dynamic (DT_NEEDED)
void ElfReader::dumpDependencies() {
    LOGI("[5. 依赖库列表 .dynamic]");
    section* sec = findSection(".dynamic");
    if (!sec) return;

    dynamic_section_accessor dynamic(reader_, sec);
    for (int i = 0; i < dynamic.get_entries_num(); ++i) {
        Elf_Xword tag, value; std::string str;
        dynamic.get_entry(i, tag, value, str);
        if (tag == DT_NEEDED) LOGI("   [DT_NEEDED] -> %s", str.c_str());
    }
}

// 6. 重定位表 (红色重点)
void ElfReader::dumpRelocations() {
    LOGI("[6. 重定位表 .rela.dyn / .rela.plt]");
    std::vector<std::string> relas = {".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt"};
    for (auto& name : relas) {
        section* sec = findSection(name);
        if (!sec) continue;
        LOGI("   >> 节名: %s", name.c_str());
        relocation_section_accessor res(reader_, sec);
        for (int i = 0; i < res.get_entries_num(); ++i) {
            Elf64_Addr offset, sym_val; std::string sym_name;
            Elf_Word type; Elf_Sxword addend, calc;
            res.get_entry(i, offset, sym_val, sym_name, type, addend, calc);
            LOGI("      偏移:0x%08llx, 类型:0x%02x, 关联符号:%s", offset, type, sym_name.c_str());
        }
    }
}

// 7. 跳转表 (红色重点)
void ElfReader::dumpJumpTables() {
    LOGI("[7. 跳转表 .plt / .got.plt 数据预览]");
    std::vector<std::string> jmps = {".plt", ".got", ".got.plt"};
    for (auto& name : jmps) {
        section* sec = findSection(name);
        if (!sec) continue;
        LOGI("   >> %s (地址:0x%llx, 大小:%llu)", name.c_str(), sec->get_address(), sec->get_size());
        dumpHex(sec->get_data(), sec->get_size() > 32 ? 32 : sec->get_size());
    }
}

// 8. 节表完整列表
void ElfReader::dumpSectionTable() {
    LOGI("[8. 节表完整列表名称/地址/大小/权限]");
    for (int i = 0; i < reader_.sections.size(); ++i) {
        const section* sec = reader_.sections[i];
        LOGI("   [%2d] %-18s 地址:0x%08llx, 大小:0x%06llx",
             i, sec->get_name().c_str(), sec->get_address(), sec->get_size());
    }
}

// 9. 特殊节
void ElfReader::dumpSpecialSections() {
    LOGI("[9. 异常/调试/只读内容]");
    // .eh_frame
    section* eh = findSection(".eh_frame");
    if (eh) LOGI("   .eh_frame: 异常回溯信息存在, 大小:%llu", eh->get_size());

    // .debug_*
    for (int i = 0; i < reader_.sections.size(); ++i) {
        std::string name = reader_.sections[i]->get_name();
        if (name.find(".debug") == 0) LOGI("   DWARF 调试信息: %s (大小:%llu)", name.c_str(), reader_.sections[i]->get_size());
    }

    // .rodata
    section* ro = findSection(".rodata");
    if (ro) {
        LOGI("   .rodata 只读数据内容预览:");
        dumpHex(ro->get_data(), ro->get_size() > 64 ? 64 : ro->get_size());
    }
}

// --- Helpers ---
void ElfReader::dumpHex(const char* data, size_t size, const std::string& prefix) {
    if (!data) return;
    std::stringstream ss;
    for (size_t i = 0; i < size; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)data[i] << " ";
        if ((i + 1) % 16 == 0 && i != size - 1) ss << "\n" << prefix;
    }
    LOGI("%s%s", prefix.c_str(), ss.str().c_str());
}

section* ElfReader::findSection(const std::string& name) {
    for (int i = 0; i < reader_.sections.size(); ++i) {
        if (reader_.sections[i]->get_name() == name) return reader_.sections[i];
    }
    return nullptr;
}