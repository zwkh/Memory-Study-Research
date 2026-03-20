#ifndef APPLICATION_MONITOR_H
#define APPLICATION_MONITOR_H

#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

enum class LogicID : int {
    LOGIC_UNKNOWN = -1,
    LOGIC_A = 0,
    LOGIC_B = 1
};

enum class MonitorType : int {
    MEMBER = 0,
    SHARE = 1
};

struct Member {
    std::string member_name;
    uint32_t start_offset;
    uint32_t end_offset;
    bool is_hot;
};

struct StructMeta {
    std::string struct_name;
    uint32_t struct_size;
    std::vector<Member> members;
};

struct MonitorBlock {
    uintptr_t address;
    size_t size;
    MonitorType monitor_type;
    StructMeta struct_meta;
    std::unordered_map<LogicID, int> logic_access_counts;
    bool is_monitored;
};

class MonitorManager {
public:
    static MonitorManager& GetInstance();
    void AddMonitorBlock(const MonitorBlock& block);
    bool GetMonitorBlock(uintptr_t addr, MonitorBlock& out_block);
    void RemoveMonitorBlock(uintptr_t addr);
    void UpdateMemberHot(uintptr_t addr, uint32_t offset);
    void UpdateLogicAccess(uintptr_t addr, LogicID logic_id);
    void ReprotectAllBlocks();

private:
    MonitorManager() = default;
    std::mutex mutex_;
    std::unordered_map<uintptr_t, MonitorBlock> monitor_map_;
};

#endif //APPLICATION_MONITOR_H