#ifndef ELF_READER_H
#define ELF_READER_H

#include <string>
#include <elfio/elfio.hpp>

class ElfReader {
public:
    static void Analyze(const char* soname);

private:
    ElfReader(const char* path);
    ~ElfReader();

    bool Load();
    void DumpAll();
    
    void DumpElfHeader();           // ELF Header
    void DumpLoadSegments();        // 段加载信息
    void DumpSectionTable();        // 节表完整列表
    void DumpDynamicSymbols();      // 动态符号表 .dynsym
    void DumpStaticSymbols();       // 静态符号表 .symtab
    void DumpDependencies();        // 依赖库列表 .dynamic
    void DumpRelocations();         // 重定位表 .rela.dyn / .rela.plt
    void DumpJumpTables();          // 跳转表 .plt / .got.plt
    void DumpSpecialSections();     // .eh_frame, .debug_*, .rodata

    void DumpHex(const char* data, size_t size, const std::string& prefix = "      ");
    ELFIO::section* FindSection(const std::string& name);
    std::string path_;
    ELFIO::elfio reader_;
    bool loaded_ = false;
};

#endif // ELF_READER_H