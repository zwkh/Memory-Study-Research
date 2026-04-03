#ifndef APPLICATION_MONITOR_H
#define APPLICATION_MONITOR_H

#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

enum class LogicID : int {
    LOGIC_UNKNOWN = 0,
    LOGIC_1 = 1,
    LOGIC_2 = 2,
    LOGIC_3 = 3,
    LOGIC_4 = 4
};

enum class MonitorType : int {
    NONE   = 0,
    MEMBER = 1 << 0,
    SHARE  = 1 << 1,
    BOTH   = MEMBER | SHARE
};

inline MonitorType operator|(MonitorType a, MonitorType b) {
    return static_cast<MonitorType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool operator&(MonitorType a, MonitorType b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

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
    size_t req_size;
    MonitorType monitor_type;
    StructMeta struct_meta;
    std::unordered_map<LogicID, int> logic_access_counts;
    bool is_monitored;
};

class PendingMonitor {
public:
    static PendingMonitor& GetInstance();
    void Pending(const StructMeta& meta);
    std::vector<StructMeta> GetStructMetas();
private:
    PendingMonitor() = default;
    std::mutex mux_;
    std::vector<StructMeta> struct_meta_;
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
    std::vector<MonitorBlock> GetAllBlocks();

private:
    MonitorManager() = default;
    std::mutex mutex_;
    std::unordered_map<uintptr_t, MonitorBlock> monitor_map_;
};

#endif //APPLICATION_MONITOR_H