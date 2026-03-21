#ifndef ELF_READER_H
#define ELF_READER_H

#include <string>
#include <elfio/elfio.hpp>

class ElfReader {
public:
    /**
     * @brief 静态分析入口
     * @param soname 动态库名称，例如 "libsample.so"
     */
    static void Analyze(const char* soname);

private:
    ElfReader(const char* path);
    ~ElfReader();

    bool load();
    void dumpAll();

    // --- 树状结构对应的解析模块 ---
    void dumpElfHeader();           // ELF Header (类型/架构/入口)
    void dumpLoadSegments();        // 段加载信息 (PT_LOAD 地址/权限)
    void dumpSectionTable();        // 节表完整列表 (名称/地址/大小/权限)
    void dumpDynamicSymbols();      // 动态符号表 .dynsym (函数地址/大小)
    void dumpStaticSymbols();       // 静态符号表 .symtab
    void dumpDependencies();        // 依赖库列表 .dynamic (DT_NEEDED)
    void dumpRelocations();         // 重定位表 .rela.dyn / .rela.plt (核心重点)
    void dumpJumpTables();          // 跳转表 .plt / .got.plt (核心重点)
    void dumpSpecialSections();     // .eh_frame, .debug_*, .rodata (异常/调试/只读)

    // --- 工具函数 ---
    void dumpHex(const char* data, size_t size, const std::string& prefix = "      ");
    ELFIO::section* findSection(const std::string& name);

    std::string path_;
    ELFIO::elfio reader_;
    bool loaded_ = false;
};

#endif // ELF_READER_H